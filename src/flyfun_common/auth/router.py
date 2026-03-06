"""Shared OAuth auth router: login, callback, logout, /auth/me.

Each app calls create_auth_router() and mounts it on their FastAPI app.
The callback creates/updates users in the shared DB and sets the
cross-subdomain JWT cookie.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from flyfun_common.auth.config import (
    COOKIE_NAME,
    create_oauth,
    get_cookie_domain,
    get_jwt_secret,
    is_dev_mode,
)
from flyfun_common.auth.jwt_utils import create_token
from flyfun_common.db.deps import current_user_id, get_db
from flyfun_common.db.models import UserRow

logger = logging.getLogger(__name__)


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

    @router.get("/login/google")
    async def login_google(request: Request, platform: str | None = None):
        redirect_uri = request.url_for("callback_google")
        if not is_dev_mode():
            redirect_uri = str(redirect_uri).replace("http://", "https://")
        if platform:
            request.session["oauth_platform"] = platform
        return await oauth.google.authorize_redirect(request, redirect_uri)

    @router.get("/callback/google")
    async def callback_google(request: Request, db: Session = Depends(get_db)):
        try:
            token = await oauth.google.authorize_access_token(request)
        except Exception as exc:
            logger.warning("OAuth callback failed: %s", exc)
            raise HTTPException(status_code=400, detail="OAuth authentication failed")

        userinfo = token.get("userinfo")
        if not userinfo:
            raise HTTPException(status_code=400, detail="No user info from Google")

        provider = "google"
        provider_sub = userinfo["sub"]
        email = userinfo.get("email", "")
        name = userinfo.get("name", email)

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
            logger.info("New user created: %s (%s)", email, user.id)

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
        if name and user.display_name != name:
            user.display_name = name
        db.flush()

        if not user.approved:
            return RedirectResponse(url="/login.html?status=pending", status_code=302)

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )

        # iOS app: redirect to custom URL scheme
        platform = request.session.pop("oauth_platform", None)
        if platform == "ios":
            from urllib.parse import quote

            app_scheme = "flyfun"
            redirect_url = f"{app_scheme}://auth/callback?token={quote(jwt_token)}"
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
