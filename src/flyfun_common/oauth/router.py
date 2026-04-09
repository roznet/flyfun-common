"""OAuth 2.1 authorization server router for MCP connectors."""

from __future__ import annotations

import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from urllib.parse import quote, urlencode, urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from flyfun_common.admin import generate_api_token, hash_token
from flyfun_common.db.deps import get_db, optional_user_id
from flyfun_common.db.models import ApiTokenRow, UserRow
from flyfun_common.oauth.models import (
    OAuthAuthorizationCodeRow,
    OAuthClientRow,
    OAuthRefreshTokenRow,
)
from flyfun_common.oauth.pkce import verify_pkce_s256

_CODE_LIFETIME = timedelta(minutes=10)


# --- Request / response models ---


class RegisterRequest(BaseModel):
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str] = ["authorization_code", "refresh_token"]
    token_endpoint_auth_method: str = "client_secret_post"


# --- Helpers ---


def _oauth_error_redirect(
    redirect_uri: str, error: str, state: str | None, description: str = ""
) -> RedirectResponse:
    """Build an OAuth error redirect per RFC 6749 §4.1.2.1."""
    params: dict[str, str] = {"error": error}
    if description:
        params["error_description"] = description
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{sep}{urlencode(params)}", status_code=302
    )


def _validate_redirect_uri(uri: str) -> bool:
    """Check that a redirect URI is HTTPS (or localhost for dev)."""
    parsed = urlparse(uri)
    if parsed.scheme == "https":
        return True
    if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"):
        return True
    return False


def _render_consent_page(
    *,
    app_name: str,
    client_name: str,
    user_email: str,
    permissions: list[str],
    # Hidden form fields for the POST
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str,
    csrf_token: str,
) -> HTMLResponse:
    """Render the OAuth consent screen as server-side HTML."""
    # Escape all user-controlled values to prevent XSS
    client_name = html_escape(client_name)
    user_email = html_escape(user_email)
    app_name = html_escape(app_name)

    permission_items = "\n".join(
        f'<li>{html_escape(p)}</li>' for p in permissions
    )

    hidden_fields = ""
    for name, value in [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge),
        ("code_challenge_method", code_challenge_method),
        ("state", state),
        ("scope", scope),
        ("csrf_token", csrf_token),
    ]:
        hidden_fields += (
            f'<input type="hidden" name="{name}" value="{html_escape(value)}">\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize – {app_name}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; display: flex; justify-content: center; padding: 40px 16px; }}
  .card {{ background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.08);
           max-width: 420px; width: 100%; padding: 32px; }}
  h1 {{ font-size: 20px; margin-bottom: 16px; }}
  .client {{ font-weight: 600; }}
  p {{ color: #555; line-height: 1.5; margin-bottom: 12px; }}
  ul {{ margin: 0 0 20px 20px; color: #333; line-height: 1.8; }}
  .user {{ background: #f0f0f0; border-radius: 6px; padding: 8px 12px; margin-bottom: 24px;
           font-size: 14px; color: #555; }}
  .buttons {{ display: flex; gap: 12px; }}
  button {{ flex: 1; padding: 10px; border: none; border-radius: 8px; font-size: 15px;
            cursor: pointer; font-weight: 500; }}
  .approve {{ background: #2563eb; color: #fff; }}
  .approve:hover {{ background: #1d4ed8; }}
  .deny {{ background: #e5e7eb; color: #333; }}
  .deny:hover {{ background: #d1d5db; }}
</style>
</head>
<body>
<div class="card">
  <h1>{app_name}</h1>
  <p><span class="client">{client_name}</span> wants to access your account.</p>
  <p>This will allow the app to:</p>
  <ul>
    {permission_items}
  </ul>
  <div class="user">Logged in as {user_email}</div>
  <form method="post" action="/oauth/authorize">
    {hidden_fields}
    <div class="buttons">
      <button type="submit" name="action" value="deny" class="deny">Cancel</button>
      <button type="submit" name="action" value="approve" class="approve">Authorize</button>
    </div>
  </form>
</div>
</body>
</html>"""
    return HTMLResponse(content=html)


# --- Router factory ---


def create_oauth_router(
    *,
    app_name: str = "FlyFun",
    scopes_supported: list[str] | None = None,
    permission_descriptions: list[str] | None = None,
    login_path: str = "/auth/login/google",
    token_expiry_days: int = 7,
) -> APIRouter:
    """Create and return a FastAPI router implementing OAuth 2.1 for MCP clients."""

    if scopes_supported is None:
        scopes_supported = ["mcp"]
    if permission_descriptions is None:
        permission_descriptions = [
            "View your flights and briefings",
            "Create flights and request weather briefings",
            "View airport weather forecasts",
        ]

    router = APIRouter(tags=["oauth"])

    # ---- Dynamic Client Registration (RFC 7591) ----

    @router.post("/oauth/register")
    async def register(body: RegisterRequest, db: Session = Depends(get_db)):
        # Validate redirect URIs
        for uri in body.redirect_uris:
            if not _validate_redirect_uri(uri):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid redirect_uri: {uri} (must be HTTPS)",
                )

        allowed_grants = {"authorization_code", "refresh_token"}
        if not set(body.grant_types).issubset(allowed_grants):
            raise HTTPException(
                status_code=400,
                detail=f"grant_types must be subset of {sorted(allowed_grants)}",
            )

        client_id = "mcp_" + secrets.token_urlsafe(16)
        client_secret = generate_api_token(prefix="mcp_secret_")

        row = OAuthClientRow(
            id=client_id,
            client_secret_hash=hash_token(client_secret),
            client_name=body.client_name,
            redirect_uris_json=json.dumps(body.redirect_uris),
        )
        db.add(row)
        db.flush()

        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.client_name,
            "redirect_uris": body.redirect_uris,
            "grant_types": body.grant_types,
        }

    # ---- Authorization Endpoint ----

    @router.get("/oauth/authorize")
    async def authorize_get(
        request: Request,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        code_challenge: str,
        code_challenge_method: str,
        state: str = "",
        scope: str = "mcp",
        db: Session = Depends(get_db),
    ):
        # Validate response_type
        if response_type != "code":
            raise HTTPException(status_code=400, detail="response_type must be 'code'")
        if code_challenge_method != "S256":
            raise HTTPException(
                status_code=400, detail="code_challenge_method must be 'S256'"
            )

        # Validate client
        client = db.query(OAuthClientRow).filter(OAuthClientRow.id == client_id).first()
        if not client:
            raise HTTPException(status_code=400, detail="Unknown client_id")

        allowed_uris = json.loads(client.redirect_uris_json)
        if redirect_uri not in allowed_uris:
            raise HTTPException(status_code=400, detail="redirect_uri not registered")

        # Check authentication
        user_id = optional_user_id(request, db)
        if user_id is None:
            # Store the full authorize URL in session so we can resume after login
            authorize_url = str(request.url)
            request.session["oauth_next"] = authorize_url
            return RedirectResponse(url=login_path, status_code=302)

        # Validate scope
        requested_scopes = scope.split()
        if not all(s in scopes_supported for s in requested_scopes):
            return _oauth_error_redirect(
                redirect_uri, "invalid_scope", state,
                f"Unsupported scope. Supported: {' '.join(scopes_supported)}",
            )

        # Authenticated — show consent screen
        user = db.query(UserRow).filter(UserRow.id == user_id).first()
        user_email = user.email if user else user_id

        # Generate CSRF token and store in session
        csrf_token = secrets.token_urlsafe(32)
        request.session["oauth_csrf"] = csrf_token

        return _render_consent_page(
            app_name=app_name,
            client_name=client.client_name or client_id,
            user_email=user_email,
            permissions=permission_descriptions,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            state=state,
            scope=scope,
            csrf_token=csrf_token,
        )

    @router.post("/oauth/authorize")
    async def authorize_post(
        request: Request,
        action: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        code_challenge: str = Form(...),
        code_challenge_method: str = Form("S256"),
        state: str = Form(""),
        scope: str = Form("mcp"),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
    ):
        # Must be authenticated
        user_id = optional_user_id(request, db)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        # Validate CSRF token
        expected_csrf = request.session.pop("oauth_csrf", None)
        if not expected_csrf or not hmac.compare_digest(csrf_token, expected_csrf):
            raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

        # Validate client + redirect_uri
        client = db.query(OAuthClientRow).filter(OAuthClientRow.id == client_id).first()
        if not client:
            raise HTTPException(status_code=400, detail="Unknown client_id")

        allowed_uris = json.loads(client.redirect_uris_json)
        if redirect_uri not in allowed_uris:
            raise HTTPException(status_code=400, detail="redirect_uri not registered")

        if action == "deny":
            return _oauth_error_redirect(redirect_uri, "access_denied", state)

        # Generate authorization code
        code = secrets.token_urlsafe(32)
        db.add(
            OAuthAuthorizationCodeRow(
                code=code,
                client_id=client_id,
                user_id=user_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                scope=scope,
                expires_at=datetime.now(timezone.utc) + _CODE_LIFETIME,
            )
        )
        db.flush()

        params: dict[str, str] = {"code": code}
        if state:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            url=f"{redirect_uri}{sep}{urlencode(params)}", status_code=302
        )

    # ---- Token Endpoint ----

    @router.post("/oauth/token")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        db: Session = Depends(get_db),
        # authorization_code params
        code: str | None = Form(None),
        redirect_uri: str | None = Form(None),
        code_verifier: str | None = Form(None),
        # shared params
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        # refresh_token params
        refresh_token: str | None = Form(None),
    ):
        # Validate client credentials
        if not client_id or not client_secret:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Missing client credentials"},
                status_code=401,
            )

        client = db.query(OAuthClientRow).filter(OAuthClientRow.id == client_id).first()
        if not client or not hmac.compare_digest(
            hash_token(client_secret), client.client_secret_hash
        ):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Bad client credentials"},
                status_code=401,
            )

        if grant_type == "authorization_code":
            return _handle_authorization_code(
                db, client, code, redirect_uri, code_verifier, token_expiry_days
            )
        elif grant_type == "refresh_token":
            return _handle_refresh_token(
                db, client, refresh_token, token_expiry_days
            )
        else:
            return JSONResponse(
                {"error": "unsupported_grant_type"}, status_code=400
            )

    return router


# --- Grant type handlers ---


def _handle_authorization_code(
    db: Session,
    client: OAuthClientRow,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
    token_expiry_days: int,
) -> JSONResponse:
    if not code or not redirect_uri or not code_verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing required parameters"},
            status_code=400,
        )

    auth_code = (
        db.query(OAuthAuthorizationCodeRow)
        .filter(OAuthAuthorizationCodeRow.code == code)
        .first()
    )
    if not auth_code:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Unknown authorization code"},
            status_code=400,
        )

    # Validate code
    now = datetime.now(timezone.utc)
    expires = auth_code.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if auth_code.used:
        # RFC 6749 §10.5: revoke all tokens issued from this code
        if auth_code.access_token_hash:
            issued_at = (
                db.query(ApiTokenRow)
                .filter(ApiTokenRow.token_hash == auth_code.access_token_hash)
                .first()
            )
            if issued_at:
                issued_at.revoked = True
            issued_rt = (
                db.query(OAuthRefreshTokenRow)
                .filter(
                    OAuthRefreshTokenRow.access_token_hash
                    == auth_code.access_token_hash
                )
                .first()
            )
            if issued_rt:
                issued_rt.revoked = True
            db.flush()
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Authorization code already used"},
            status_code=400,
        )
    if expires <= now:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Authorization code expired"},
            status_code=400,
        )
    if auth_code.client_id != client.id:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Client mismatch"},
            status_code=400,
        )
    if auth_code.redirect_uri != redirect_uri:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # PKCE verification
    if not verify_pkce_s256(code_verifier, auth_code.code_challenge):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    # Mark code as used
    auth_code.used = True

    # Issue access token
    access_token = generate_api_token()
    access_hash = hash_token(access_token)
    expires_at = now + timedelta(days=token_expiry_days)

    db.add(
        ApiTokenRow(
            user_id=auth_code.user_id,
            token_hash=access_hash,
            name=client.client_name or client.id,
            expires_at=expires_at,
            oauth_client_id=client.id,
        )
    )

    # Link tokens back to auth code for replay revocation
    auth_code.access_token_hash = access_hash
    db.flush()

    # Issue refresh token
    refresh_plain = generate_api_token(prefix="ffr_")
    refresh_hash = hash_token(refresh_plain)
    db.add(
        OAuthRefreshTokenRow(
            token_hash=refresh_hash,
            client_id=client.id,
            user_id=auth_code.user_id,
            access_token_hash=access_hash,
            scope=auth_code.scope,
        )
    )
    db.flush()

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": token_expiry_days * 86400,
        "refresh_token": refresh_plain,
    })


def _handle_refresh_token(
    db: Session,
    client: OAuthClientRow,
    refresh_token_str: str | None,
    token_expiry_days: int,
) -> JSONResponse:
    if not refresh_token_str:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing refresh_token"},
            status_code=400,
        )

    rt_hash = hash_token(refresh_token_str)
    rt = (
        db.query(OAuthRefreshTokenRow)
        .filter(OAuthRefreshTokenRow.token_hash == rt_hash)
        .first()
    )
    if not rt or rt.revoked:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid refresh token"},
            status_code=400,
        )
    if rt.expires_at:
        exp = rt.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token expired"},
                status_code=400,
            )
    if rt.client_id != client.id:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Client mismatch"},
            status_code=400,
        )

    # Revoke old access token
    old_at = (
        db.query(ApiTokenRow)
        .filter(ApiTokenRow.token_hash == rt.access_token_hash)
        .first()
    )
    if old_at:
        old_at.revoked = True

    # Revoke old refresh token
    rt.revoked = True

    # Issue new access token
    now = datetime.now(timezone.utc)
    access_token = generate_api_token()
    access_hash = hash_token(access_token)
    expires_at = now + timedelta(days=token_expiry_days)

    db.add(
        ApiTokenRow(
            user_id=rt.user_id,
            token_hash=access_hash,
            name=client.client_name or client.id,
            expires_at=expires_at,
            oauth_client_id=client.id,
        )
    )

    # Issue new refresh token (rotation)
    new_refresh = generate_api_token(prefix="ffr_")
    new_refresh_hash = hash_token(new_refresh)
    db.add(
        OAuthRefreshTokenRow(
            token_hash=new_refresh_hash,
            client_id=client.id,
            user_id=rt.user_id,
            access_token_hash=access_hash,
            scope=rt.scope,
        )
    )
    db.flush()

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": token_expiry_days * 86400,
        "refresh_token": new_refresh,
    })
