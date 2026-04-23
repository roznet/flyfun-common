"""Shared OAuth auth router: login, callback, logout, /auth/me.

Each app calls create_auth_router() and mounts it on their FastAPI app.
The callback creates/updates users in the shared DB and sets the
cross-subdomain JWT cookie.

Supports multiple OAuth providers (Google, Apple, etc.) via generic
/{provider} routes.  Also supports native iOS Sign in with Apple via
POST /auth/apple/token (identity token validation).
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from flyfun_common.auth.config import (
    COOKIE_NAME,
    SUPPORTED_PROVIDERS,
    create_oauth,
    get_cookie_domain,
    get_jwt_secret,
    get_session_cookie_attrs,
    is_dev_mode,
)
from flyfun_common.auth.jwt_utils import create_token, get_jwt_cookie_max_age
from flyfun_common.db.deps import current_user_id, get_db
from flyfun_common.db.models import ApiTokenRow, UserPreferencesRow, UserRow

logger = logging.getLogger(__name__)

# Apple's JWKS endpoint for verifying identity tokens
_APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"
_apple_jwks_client: pyjwt.PyJWKClient | None = None


def _is_safe_relative_path(value: str) -> bool:
    """True if `value` is a safe same-origin redirect target.

    Blocks open-redirect vectors: absolute URLs, protocol-relative `//host`,
    backslash-prefixed `/\\host` (some browsers normalize this to `//host`),
    and anything with a scheme or netloc.
    """
    if not isinstance(value, str) or not value:
        return False
    if not value.startswith("/"):
        return False
    if value.startswith("//") or value.startswith("/\\"):
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme == "" and parsed.netloc == ""


def _get_apple_jwks_client() -> pyjwt.PyJWKClient:
    """Lazily create a cached JWKS client for Apple's public keys."""
    global _apple_jwks_client
    if _apple_jwks_client is None:
        _apple_jwks_client = pyjwt.PyJWKClient(_APPLE_JWKS_URL, cache_keys=True)
    return _apple_jwks_client


def _extract_userinfo(provider: str, token: dict) -> tuple[str, str, str]:
    """Extract (sub, email, display_name) from an OAuth token response.

    Each provider returns user data differently:
    - Google: standard OIDC userinfo with sub, email, name
    - Apple: sub/email in id_token claims; name only on first login via
             a separate 'user' JSON field in the POST body
    """
    if provider == "apple":
        # Apple puts claims in the id_token (parsed by authlib into userinfo)
        userinfo = token.get("userinfo") or {}
        sub = userinfo.get("sub", "")
        email = userinfo.get("email", "")
        # Apple only sends the user's name on first authorization.
        # It comes as a JSON blob in the POST body 'user' parameter,
        # which authlib does NOT parse automatically — we handle it in
        # the callback and pass it via the token dict.
        user_data = token.get("_apple_user", {})
        name_parts = user_data.get("name", {})
        first = name_parts.get("firstName", "")
        last = name_parts.get("lastName", "")
        name = f"{first} {last}".strip() or email
        return sub, email, name

    # Default: Google and other standard OIDC providers
    userinfo = token.get("userinfo")
    if not userinfo:
        raise ValueError(f"No userinfo in token from {provider}")
    return userinfo["sub"], userinfo.get("email", ""), userinfo.get("name", "")


def _find_or_create_user(
    db: Session,
    provider: str,
    provider_sub: str,
    email: str,
    name: str,
    on_new_user: callable | None = None,
    request: Request | None = None,
) -> UserRow:
    """Find an existing user by (provider, provider_sub) or create a new one.

    Updates email/name on returning users if changed.
    """
    user = (
        db.query(UserRow)
        .filter_by(provider=provider, provider_sub=provider_sub)
        .first()
    )
    if user is None:
        user = UserRow(
            id=str(uuid.uuid4()),
            provider=provider,
            provider_sub=provider_sub,
            email=email,
            display_name=name,
            approved=True,
        )
        db.add(user)
        db.flush()
        logger.info("New user created via %s: %s", provider, user.id)

        if on_new_user and request:
            try:
                on_new_user(user, request, db)
            except Exception:
                logger.warning(
                    "on_new_user callback failed for %s", user.id, exc_info=True
                )

    user.last_login_at = datetime.now(timezone.utc)
    if email and user.email != email:
        user.email = email
    # Only update name if we got a real name (not just the email echoed back)
    if name and name != email and user.display_name != name:
        user.display_name = name
    db.flush()
    return user


class AppleTokenRequest(BaseModel):
    """Request body for native iOS Sign in with Apple."""

    identity_token: str
    first_name: str | None = None
    last_name: str | None = None


def create_auth_router(
    on_new_user: callable | None = None,
    on_delete_user: callable | None = None,
) -> APIRouter:
    """Create an auth router.

    Args:
        on_new_user: Optional callback(user: UserRow, request: Request, db: Session)
                     called after a new user is created (e.g. send welcome email).
        on_delete_user: Optional callback(user_id: str, db: Session) called before
                        deleting a user, so apps can clean up app-specific data.
    """
    router = APIRouter(prefix="/auth", tags=["auth"])
    oauth = create_oauth()

    def _get_oauth_client(provider: str):
        """Get a registered OAuth client, or raise 404."""
        client = getattr(oauth, provider, None)
        if client is None:
            raise HTTPException(
                status_code=404,
                detail=f"Auth provider '{provider}' is not configured",
            )
        return client

    @router.get("/providers")
    async def list_providers():
        """Return the list of configured OAuth providers."""
        from flyfun_common.auth.config import get_registered_providers

        return {"providers": get_registered_providers(oauth)}

    @router.get("/login/{provider}")
    async def login(
        provider: str,
        request: Request,
        platform: str | None = None,
        scheme: str | None = None,
        next: str | None = None,
    ):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
        client = _get_oauth_client(provider)
        redirect_uri = request.url_for("callback", provider=provider)
        if not is_dev_mode():
            redirect_uri = str(redirect_uri).replace("http://", "https://")
        if platform:
            request.session["oauth_platform"] = platform
        if scheme:
            if not re.fullmatch(r"flyfun[a-z0-9\-]*", scheme):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid URL scheme",
                )
            request.session["oauth_scheme"] = scheme
        # Post-login redirect — honored only on browser/web flow, not native iOS.
        # Silently dropped if it doesn't pass open-redirect validation.
        if next and platform != "ios" and _is_safe_relative_path(next):
            request.session["post_login_redirect"] = next
        return await client.authorize_redirect(request, redirect_uri)

    @router.get("/callback/{provider}")
    @router.post("/callback/{provider}")  # Apple uses form_post (POST)
    async def callback(
        provider: str, request: Request, db: Session = Depends(get_db)
    ):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
        client = _get_oauth_client(provider)

        try:
            token = await client.authorize_access_token(request)
        except Exception as exc:
            logger.warning("OAuth callback failed for %s: %s", provider, exc)
            raise HTTPException(
                status_code=400, detail="OAuth authentication failed"
            )

        # Apple: extract the 'user' JSON from form body (only sent on first auth)
        if provider == "apple":
            form = await request.form()
            user_json = form.get("user")
            if user_json:
                try:
                    token["_apple_user"] = json.loads(user_json)
                except (json.JSONDecodeError, TypeError):
                    pass

        try:
            provider_sub, email, name = _extract_userinfo(provider, token)
        except (ValueError, KeyError) as exc:
            logger.warning("Failed to extract userinfo from %s: %s", provider, exc)
            raise HTTPException(
                status_code=400, detail=f"No user info from {provider}"
            )

        if not provider_sub:
            raise HTTPException(
                status_code=400, detail=f"No subject identifier from {provider}"
            )

        user = _find_or_create_user(
            db, provider, provider_sub, email, name,
            on_new_user=on_new_user, request=request,
        )

        if not user.approved:
            return RedirectResponse(url="/login.html?status=pending", status_code=302)

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )

        # iOS/native app: redirect to app-specific custom URL scheme
        platform = request.session.pop("oauth_platform", None)
        # iOS flow doesn't honor post-login redirect — the app owns navigation.
        post_login_redirect = request.session.pop("post_login_redirect", None)
        if platform == "ios":
            scheme = request.session.pop("oauth_scheme", "flyfun")
            redirect_url = f"{scheme}://auth/callback?token={quote(jwt_token)}"
            return RedirectResponse(url=redirect_url, status_code=302)

        # Resume OAuth authorize flow if we were redirected here from /oauth/authorize
        oauth_next = request.session.pop("oauth_next", None)
        if oauth_next and urlparse(oauth_next).path.startswith("/oauth/"):
            response = RedirectResponse(url=oauth_next, status_code=302)
            _set_session_cookie(response, jwt_token)
            return response

        # Deep-link return from consumer app: validated at stash time.
        target = post_login_redirect if post_login_redirect and _is_safe_relative_path(post_login_redirect) else "/"
        response = RedirectResponse(url=target, status_code=302)
        _set_session_cookie(response, jwt_token)
        return response

    # --- Native iOS Sign in with Apple ---

    @router.post("/apple/token")
    async def apple_token(
        body: AppleTokenRequest,
        request: Request,
        db: Session = Depends(get_db),
    ):
        """Validate an Apple identity token from a native iOS app.

        The iOS app uses ASAuthorizationAppleIDProvider to get an identity
        token (JWT signed by Apple), then sends it here. We verify the
        signature against Apple's public keys and extract the user info.

        Returns a flyfun JWT token for the app to use in subsequent requests.
        """
        # Build the list of accepted audiences.
        # APPLE_APP_IDS: comma-separated bundle IDs for all iOS apps
        #   e.g. "aero.flyfun.weather,aero.flyfun.customs"
        # Falls back to APPLE_APP_ID (single app) or APPLE_CLIENT_ID (web).
        app_ids_raw = os.environ.get("APPLE_APP_IDS", "")
        if app_ids_raw:
            expected_audiences = [a.strip() for a in app_ids_raw.split(",") if a.strip()]
        else:
            single = os.environ.get(
                "APPLE_APP_ID",
                os.environ.get("APPLE_CLIENT_ID", ""),
            )
            expected_audiences = [single] if single else []

        if not expected_audiences:
            raise HTTPException(
                status_code=503,
                detail="Apple Sign In is not configured on this server",
            )

        try:
            jwks_client = _get_apple_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(body.identity_token)

            # PyJWT accepts a list of audiences — token is valid if its
            # aud matches ANY of them.
            claims = pyjwt.decode(
                body.identity_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=expected_audiences,
                issuer="https://appleid.apple.com",
            )
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Identity token has expired")
        except pyjwt.InvalidTokenError as exc:
            logger.warning("Apple identity token validation failed: %s", exc)
            raise HTTPException(status_code=401, detail="Invalid identity token")

        sub = claims.get("sub", "")
        email = claims.get("email", "")
        if not sub:
            raise HTTPException(status_code=400, detail="No subject in identity token")

        # Build display name from optional first_name/last_name
        # (only available on first iOS authorization)
        name_parts = [p for p in [body.first_name, body.last_name] if p]
        name = " ".join(name_parts) or email

        user = _find_or_create_user(
            db, "apple", sub, email, name,
            on_new_user=on_new_user, request=request,
        )

        if not user.approved:
            raise HTTPException(status_code=403, detail="Account is not approved")

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )

        return {"token": jwt_token, "user_id": user.id}

    @router.post("/logout")
    async def logout():
        response = RedirectResponse(url="/login.html", status_code=302)
        response.delete_cookie(COOKIE_NAME, path="/", domain=get_cookie_domain())
        return response

    @router.get("/me")
    async def get_me(
        user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
    ):
        user = db.get(UserRow, user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {
            "id": user.id,
            "email": user.email,
            "name": user.display_name,
            "approved": user.approved,
        }

    @router.delete("/account", status_code=204)
    async def delete_account(
        user_id: str = Depends(current_user_id), db: Session = Depends(get_db)
    ):
        """Delete the authenticated user's account and all associated data.

        The on_delete_user callback is called first so apps can clean up their
        own data.  If the callback raises, the entire transaction is rolled back
        (fail-closed: better to block deletion than leave partial state).
        """
        logger.info("Account deletion requested for user %s", user_id)

        # Let the app clean up its own data first
        if on_delete_user:
            on_delete_user(user_id, db)

        # Delete shared tables (cost_ledger rows are intentionally kept for
        # audit/reporting — CostLedgerRow has no FK cascade on users)
        db.query(UserPreferencesRow).filter(UserPreferencesRow.user_id == user_id).delete()
        db.query(ApiTokenRow).filter(ApiTokenRow.user_id == user_id).delete()
        db.query(UserRow).filter(UserRow.id == user_id).delete()

        logger.info("Account deleted for user %s", user_id)

        response = Response(status_code=204)
        response.delete_cookie(COOKIE_NAME, path="/", domain=get_cookie_domain())
        return response

    return router


def _set_session_cookie(response: RedirectResponse, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=get_jwt_cookie_max_age(),
        **get_session_cookie_attrs(),
    )
