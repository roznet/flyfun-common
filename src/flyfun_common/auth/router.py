"""Shared OAuth auth router: login, callback, logout, /auth/me.

Each app calls create_auth_router() and mounts it on their FastAPI app.
The callback creates/updates users in the shared DB and sets the
cross-subdomain JWT cookie.

Supports multiple OAuth providers (Google, Apple, etc.) via generic
/{provider} routes.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from flyfun_common.auth.config import (
    COOKIE_NAME,
    SUPPORTED_PROVIDERS,
    create_oauth,
    get_cookie_domain,
    get_jwt_secret,
    is_dev_mode,
)
from flyfun_common.auth.jwt_utils import create_token
from flyfun_common.db.deps import current_user_id, get_db
from flyfun_common.db.models import UserRow

logger = logging.getLogger(__name__)


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


def create_auth_router(
    on_new_user: callable | None = None,
) -> APIRouter:
    """Create an auth router.

    Args:
        on_new_user: Optional callback(user: UserRow, request: Request, db: Session)
                     called after a new user is created (e.g. send welcome email).
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
    async def login(provider: str, request: Request, platform: str | None = None):
        if provider not in SUPPORTED_PROVIDERS:
            raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
        client = _get_oauth_client(provider)
        redirect_uri = request.url_for("callback", provider=provider)
        if not is_dev_mode():
            redirect_uri = str(redirect_uri).replace("http://", "https://")
        if platform:
            request.session["oauth_platform"] = platform
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
            logger.info("New user created via %s: %s (%s)", provider, email, user.id)

            if on_new_user:
                try:
                    on_new_user(user, request, db)
                except Exception:
                    logger.warning(
                        "on_new_user callback failed for %s", email, exc_info=True
                    )

        user.last_login_at = datetime.now(timezone.utc)
        if email and user.email != email:
            user.email = email
        if name and name != email and user.display_name != name:
            user.display_name = name
        db.flush()

        if not user.approved:
            return RedirectResponse(url="/login.html?status=pending", status_code=302)

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )

        # iOS/native app: redirect to custom URL scheme
        platform = request.session.pop("oauth_platform", None)
        if platform == "ios":
            redirect_url = f"flyfun://auth/callback?token={quote(jwt_token)}"
            return RedirectResponse(url=redirect_url, status_code=302)

        response = RedirectResponse(url="/", status_code=302)
        _set_session_cookie(response, jwt_token)
        return response

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

    return router


def _set_session_cookie(response: RedirectResponse, token: str) -> None:
    secure = not is_dev_mode()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
        domain=get_cookie_domain(),
        max_age=7 * 24 * 3600,
    )
