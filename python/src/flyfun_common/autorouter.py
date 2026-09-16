"""Autorouter OAuth2 integration: link/unlink user accounts, token storage.

Autorouter uses a standard OAuth2 Authorization Code flow. Unlike
Google/Apple, this is NOT a login provider — it links an existing
flyfun user to their Autorouter account so we can call the Autorouter
API on their behalf (NOTAMs, flight plans, weather).

Tokens last ~1 year with no refresh mechanism.  When expired, the user
must re-link.

Also hosts the small read client for the user's recent routes
(``router/logs``), which several flyfun apps offer as an "Import from
Autorouter" picker. It lives here rather than in each app because this module
already owns the token: one copy of the payload quirks, one place that clears a
revoked token.

Env vars:
    AUTOROUTER_CLIENT_ID      – registered app ID (e.g. "flyfun_weather")
    AUTOROUTER_CLIENT_SECRET  – app secret from Autorouter
"""

from __future__ import annotations

import logging
import os
import secrets
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from flyfun_common.auth.config import is_dev_mode
from flyfun_common.credentials import load_encrypted_creds, save_encrypted_creds
from flyfun_common.db.deps import current_user_id, get_db

logger = logging.getLogger(__name__)

AUTOROUTER_AUTHORIZE_URL = "https://www.autorouter.aero/authorize"
AUTOROUTER_TOKEN_URL = "https://api.autorouter.aero/v1.0/oauth2/token"
AUTOROUTER_LOGS_URL = "https://api.autorouter.aero/v1.0/router/logs"

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


def create_autorouter_router(*, success_redirect: str = "/settings.html?autorouter=linked") -> APIRouter:
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

        return RedirectResponse(url=success_redirect, status_code=302)

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


# ---------------------------------------------------------------------------
# Recent routes ("Import from Autorouter")
# ---------------------------------------------------------------------------


class AutorouterRoute(BaseModel):
    """One row in an "Import from Autorouter" picker.

    A curated subset of an Autorouter ``router/logs`` entry: enough to render a
    picker row, plus the raw ``fplan`` the consumer parses into a route. Apps
    parse the plan with their own ICAO FPL parser (``euro_aip.parse_icao_fpl``
    server-side, ``RZFlight.ICAOFlightPlanParser`` on iOS) rather than this
    module growing a parser it doesn't need.
    """

    routeid: str
    departure: str
    destination: str
    departure_name: str | None = None
    destination_name: str | None = None
    departure_time: str | None = None  # ISO 8601 UTC, derived from Unix epoch
    fplan: str
    route_distance_nm: int | None = None
    aircraft_description: str | None = None
    callsign: str | None = None


class AutorouterRoutesResponse(BaseModel):
    routes: list[AutorouterRoute] = []


class AutorouterNotLinked(Exception):
    """No usable Autorouter token for this user (never linked, or revoked)."""


class AutorouterUnavailable(Exception):
    """Autorouter could not be reached, or answered with something unusable.

    ``detail`` separates "we never got an answer" from "the answer made no
    sense", which the HTTP endpoints surface as distinct 502 details so a client
    can tell a transient network problem from an upstream change.
    """

    def __init__(self, message: str, detail: str = "autorouter_unreachable") -> None:
        super().__init__(message)
        self.detail = detail


def clear_autorouter_token(db: Session, user_id: str) -> None:
    """Remove the stored Autorouter access token after a 401.

    Only touches the ``autorouter`` key inside the encrypted-creds blob, so any
    other credentials the user has stored are preserved. After this returns,
    ``/autorouter/status`` reports the account as unlinked and the app can
    prompt for a re-link.
    """
    creds = load_encrypted_creds(db, user_id) or {}
    if _CREDS_KEY in creds:
        del creds[_CREDS_KEY]
        save_encrypted_creds(db, user_id, creds)


def _epoch_to_iso(value: object) -> str | None:
    """Convert an Autorouter Unix-epoch field to ISO 8601 UTC."""
    try:
        epoch = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# The /logs endpoint historically returned a bare JSON array; the current
# implementation wraps it in a dict. Known wrapper keys are checked before
# falling back to "the first list value", so an unrelated list Autorouter might
# add later (pagination links, say) can't silently be read as the routes.
_ROUTES_LIST_KEYS = ("logs", "items", "routes", "data", "results")


def _extract_entries(payload: object) -> list[dict]:
    """Pull the list of log entries out of whatever shape Autorouter returned."""
    if isinstance(payload, list):
        entries: object = payload
    elif isinstance(payload, dict):
        entries = next(
            (payload[key] for key in _ROUTES_LIST_KEYS if isinstance(payload.get(key), list)),
            None,
        )
        if entries is None:
            entries = next((v for v in payload.values() if isinstance(v, list)), None)
        if entries is None:
            logger.warning(
                "Autorouter router/logs returned a dict with no list value; keys=%r",
                list(payload.keys()),
            )
            raise AutorouterUnavailable(
                "router/logs returned a dict with no list value",
                detail="autorouter_upstream_error",
            )
    else:
        logger.warning(
            "Autorouter router/logs returned unexpected payload shape: %r",
            type(payload).__name__,
        )
        raise AutorouterUnavailable(
            f"router/logs returned {type(payload).__name__}",
            detail="autorouter_upstream_error",
        )
    return [entry for entry in entries if isinstance(entry, dict)]


def parse_recent_routes(payload: object) -> list[AutorouterRoute]:
    """Normalise a ``router/logs`` payload into picker rows.

    Pure, so the payload quirks are unit-testable without a network or a DB.
    Rows missing any field needed to render *or* to import are dropped rather
    than surfaced half-usable.
    """
    routes: list[AutorouterRoute] = []
    for entry in _extract_entries(payload):
        fplan = entry.get("fplan")
        routeid = entry.get("routeid")
        departure = entry.get("departure")
        destination = entry.get("destination")
        if not (fplan and routeid and departure and destination):
            continue
        routes.append(
            AutorouterRoute(
                routeid=str(routeid),
                departure=str(departure),
                destination=str(destination),
                departure_name=entry.get("departurename") or None,
                destination_name=entry.get("destinationname") or None,
                departure_time=_epoch_to_iso(entry.get("departuretime")),
                fplan=str(fplan),
                route_distance_nm=_coerce_int(entry.get("routedistance")),
                aircraft_description=entry.get("aircraftdescription") or None,
                callsign=entry.get("callsign") or None,
            )
        )
    return routes


def list_recent_routes(token: str, limit: int = 25, *, timeout: float = 15.0) -> list[AutorouterRoute]:
    """Fetch the recent routes for an Autorouter bearer token.

    Raises ``AutorouterNotLinked`` on a 401 (the token is expired or revoked)
    and ``AutorouterUnavailable`` for anything else that leaves us without a
    usable list.
    """
    try:
        response = httpx.get(
            AUTOROUTER_LOGS_URL,
            # `order`/`sort` keep the newest route first, which is what a
            # picker wants and what flyfun-weather's copy of this call asked
            # for before it moved here.
            params={
                "limit": max(1, min(limit, 100)),
                "order": "desc",
                "sort": "departuretime",
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        logger.warning("Autorouter router/logs request failed: %s", exc)
        raise AutorouterUnavailable("autorouter unreachable") from exc

    if response.status_code == 401:
        raise AutorouterNotLinked("autorouter rejected the stored token")
    if response.status_code != 200:
        logger.warning(
            "Autorouter router/logs returned %s: %s",
            response.status_code,
            response.text[:200],
        )
        raise AutorouterUnavailable(
            f"autorouter returned {response.status_code}",
            detail="autorouter_upstream_error",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        logger.warning("Autorouter router/logs returned non-JSON")
        raise AutorouterUnavailable(
            "autorouter returned non-JSON", detail="autorouter_upstream_error"
        ) from exc

    return parse_recent_routes(payload)


def fetch_recent_routes(
    db: Session,
    user_id: str,
    limit: int = 25,
    *,
    token_loader: Callable[[Session, str], str | None] | None = None,
) -> list[AutorouterRoute]:
    """Recent Autorouter routes for a flyfun user.

    ``token_loader`` exists so an app with a richer token story can pass its own
    (flyfun-weather exchanges dev username/password credentials for a token).
    ``None`` means the stored OAuth token, resolved *at call time* rather than
    bound as a default argument: a default is captured when the function is
    defined, which would make the resolution invisible to a test or a caller
    that replaces it on the module.

    A 401 means the stored token is dead, so it is cleared before re-raising:
    the user is then reported as unlinked and prompted to re-link rather than
    hitting the same 401 on every visit.
    """
    loader = token_loader or get_autorouter_token
    token = loader(db, user_id)
    if not token:
        raise AutorouterNotLinked("no autorouter token stored")
    try:
        return list_recent_routes(token, limit)
    except AutorouterNotLinked:
        clear_autorouter_token(db, user_id)
        raise


def create_autorouter_routes_router(
    *,
    prefix: str = "/api/autorouter",
    token_loader: Callable[[Session, str], str | None] | None = None,
) -> APIRouter:
    """Mountable ``GET {prefix}/routes`` for an "Import from Autorouter" picker.

    Answers 409 ``autorouter_not_linked`` when there is no usable token, which
    is the client's cue to point the pilot at the account-linking page, and 502
    when Autorouter itself is the problem.
    """
    router = APIRouter(prefix=prefix, tags=["autorouter"])

    @router.get("/routes", response_model=AutorouterRoutesResponse)
    def list_routes(
        limit: int = 25,
        user_id: str = Depends(current_user_id),
        db: Session = Depends(get_db),
    ) -> AutorouterRoutesResponse:
        try:
            routes = fetch_recent_routes(db, user_id, limit, token_loader=token_loader)
        except AutorouterNotLinked:
            raise HTTPException(status_code=409, detail="autorouter_not_linked")
        except AutorouterUnavailable as exc:
            raise HTTPException(status_code=502, detail=exc.detail)
        return AutorouterRoutesResponse(routes=routes)

    return router
