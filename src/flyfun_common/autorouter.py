"""Autorouter OAuth2 integration: link/unlink user accounts, token storage.

Autorouter uses a standard OAuth2 Authorization Code flow. Unlike
Google/Apple, this is NOT a login provider — it links an existing
flyfun user to their Autorouter account so we can call the Autorouter
API on their behalf (NOTAMs, flight plans, weather).

Tokens last ~1 year with no refresh mechanism.  When expired, the user
must re-link.

Env vars:
    AUTOROUTER_CLIENT_ID      – registered app ID (e.g. "flyfun_weather")
    AUTOROUTER_CLIENT_SECRET  – app secret from Autorouter
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from flyfun_common.auth.config import is_dev_mode
from flyfun_common.credentials import load_encrypted_creds, save_encrypted_creds
from flyfun_common.db.deps import current_user_id, get_db

logger = logging.getLogger(__name__)

AUTOROUTER_AUTHORIZE_URL = "https://www.autorouter.aero/authorize"
AUTOROUTER_TOKEN_URL = "https://api.autorouter.aero/v1.0/oauth2/token"

_CREDS_KEY = "autorouter"


def _get_client_id() -> str:
    return os.environ.get("AUTOROUTER_CLIENT_ID", "")


def _get_client_secret() -> str:
    return os.environ.get("AUTOROUTER_CLIENT_SECRET", "")


def _store_token(db: Session, user_id: str, token_data: dict) -> None:
    """Store the Autorouter access token in encrypted credentials."""
    creds = load_encrypted_creds(db, user_id) or {}
    creds[_CREDS_KEY] = {
        "access_token": token_data["access_token"],
        "token_type": token_data.get("token_type", "bearer"),
        "expires_in": token_data.get("expires_in"),
        "linked_at": datetime.now(timezone.utc).isoformat(),
    }
    save_encrypted_creds(db, user_id, creds)


def get_autorouter_token(db: Session, user_id: str) -> str | None:
    """Retrieve the stored Autorouter access token for a user.

    Returns the token string, or None if the user hasn't linked.
    """
    creds = load_encrypted_creds(db, user_id)
    if not creds:
        return None
    ar = creds.get(_CREDS_KEY)
    if not ar:
        return None
    return ar.get("access_token")


def create_autorouter_router() -> APIRouter:
    """Create a router for Autorouter OAuth account linking.

    Provides:
        GET  /autorouter/link              – start OAuth flow (redirects to Autorouter)
        GET  /auth/callback/autorouter     – handle redirect back from Autorouter
        GET  /autorouter/status            – check if user has linked account
        POST /autorouter/unlink            – remove stored token
    """
    router = APIRouter(tags=["autorouter"])

    @router.get("/autorouter/link")
    async def link(request: Request, user_id: str = Depends(current_user_id)):
        """Redirect the user to Autorouter's authorization page."""
        client_id = _get_client_id()
        if not client_id:
            raise HTTPException(
                status_code=503,
                detail="Autorouter integration is not configured",
            )

        # Generate state token and store in session for CSRF protection
        state = secrets.token_urlsafe(32)
        request.session["autorouter_state"] = state
        request.session["autorouter_user_id"] = user_id

        redirect_uri = request.url_for("autorouter_callback")
        if not is_dev_mode():
            redirect_uri = str(redirect_uri).replace("http://", "https://")

        authorize_url = (
            f"{AUTOROUTER_AUTHORIZE_URL}"
            f"?client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&state={state}"
        )
        return RedirectResponse(url=authorize_url, status_code=302)

    @router.get("/auth/callback/autorouter", name="autorouter_callback")
    async def callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        db: Session = Depends(get_db),
    ):
        """Exchange the authorization code for an access token."""
        # Validate state to prevent CSRF
        expected_state = request.session.pop("autorouter_state", None)
        user_id = request.session.pop("autorouter_user_id", None)

        if not state or state != expected_state:
            raise HTTPException(status_code=400, detail="Invalid OAuth state")

        if not user_id:
            raise HTTPException(status_code=401, detail="Session expired, please retry")

        if not code:
            raise HTTPException(status_code=400, detail="No authorization code received")

        redirect_uri = request.url_for("autorouter_callback")
        if not is_dev_mode():
            redirect_uri = str(redirect_uri).replace("http://", "https://")

        # Exchange code for token — must happen within 30 seconds
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                AUTOROUTER_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": _get_client_id(),
                    "client_secret": _get_client_secret(),
                    "code": code,
                    "redirect_uri": str(redirect_uri),
                },
            )

        if resp.status_code != 200:
            logger.warning(
                "Autorouter token exchange failed: %s %s",
                resp.status_code,
                resp.text,
            )
            raise HTTPException(
                status_code=502,
                detail="Failed to exchange authorization code with Autorouter",
            )

        token_data = resp.json()
        if "access_token" not in token_data:
            logger.warning("Autorouter token response missing access_token: %s", token_data)
            raise HTTPException(
                status_code=502,
                detail="Invalid token response from Autorouter",
            )

        _store_token(db, user_id, token_data)
        logger.info("User %s linked Autorouter account", user_id)

        return RedirectResponse(url="/settings?autorouter=linked", status_code=302)

    @router.get("/autorouter/status")
    async def status(
        user_id: str = Depends(current_user_id),
        db: Session = Depends(get_db),
    ):
        """Check whether the user has a linked Autorouter account."""
        creds = load_encrypted_creds(db, user_id)
        ar = (creds or {}).get(_CREDS_KEY)
        return {
            "linked": ar is not None,
            "linked_at": ar.get("linked_at") if ar else None,
        }

    @router.post("/autorouter/unlink")
    async def unlink(
        user_id: str = Depends(current_user_id),
        db: Session = Depends(get_db),
    ):
        """Remove stored Autorouter credentials."""
        creds = load_encrypted_creds(db, user_id) or {}
        if _CREDS_KEY in creds:
            del creds[_CREDS_KEY]
            save_encrypted_creds(db, user_id, creds)
            logger.info("User %s unlinked Autorouter account", user_id)
        return {"linked": False}

    return router
