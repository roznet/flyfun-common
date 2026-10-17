"""get_db commits before the response is sent (flyfun-weather #784).

FastAPI runs a ``"request"``-scoped yield dependency's teardown after the
response has gone out, so with a bare ``Depends(get_db)`` a client's immediate
follow-up request could read the pre-write state, and a failed commit was never
reported. ``Depends(get_db, scope="function")`` commits before anything is sent.

The DB is a file so the check at ``http.response.start`` runs in its own
session on its own connection, the way a second request would.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from flyfun_common.db import engine as db_engine
from flyfun_common.db.deps import find_request_scoped_db, get_db
from flyfun_common.db.models import Base, UserRow


@pytest.fixture
def file_db(tmp_path):
    db_engine.reset_engine()
    engine = db_engine.get_engine(f"sqlite:///{tmp_path}/scope.db")
    Base.metadata.create_all(engine)
    yield
    db_engine.reset_engine()


def _app_seeing_writes_at_response_start(seen: dict, db_dependency) -> FastAPI:
    app = FastAPI()

    @app.post("/users/{user_id}")
    def create_user(user_id: str, db: Session = db_dependency):
        db.add(UserRow(id=user_id, email=f"{user_id}@example.com", display_name=user_id))
        return {"id": user_id}

    inner = app.build_middleware_stack

    def build():
        downstream = inner()

        async def asgi(scope, receive, send):
            async def watch(message):
                if message["type"] == "http.response.start" and "visible" not in seen:
                    with db_engine.SessionLocal() as fresh:
                        user_id = scope["path"].rsplit("/", 1)[-1]
                        seen["visible"] = fresh.get(UserRow, user_id) is not None
                await send(message)

            await downstream(scope, receive, watch)

        return asgi

    app.build_middleware_stack = build
    return app


def test_function_scope_commits_before_the_response_starts(file_db):
    seen: dict = {}
    app = _app_seeing_writes_at_response_start(seen, Depends(get_db, scope="function"))
    assert TestClient(app).post("/users/u1").status_code == 200
    assert seen == {"visible": True}


def test_request_scope_commits_only_after_the_response_starts(file_db):
    # The #784 race, kept as a control: proves the check above can fail.
    seen: dict = {}
    app = _app_seeing_writes_at_response_start(seen, Depends(get_db))
    assert TestClient(app).post("/users/u1").status_code == 200
    assert seen == {"visible": False}


def test_a_failed_commit_reaches_the_client(file_db):
    with db_engine.SessionLocal() as s:
        s.add(UserRow(id="dup", email="dup@example.com", display_name="dup"))
        s.commit()
    app = FastAPI()

    @app.post("/dup")
    def add_duplicate(db: Session = Depends(get_db, scope="function")):
        db.add(UserRow(id="dup", email="other@example.com", display_name="dup"))
        return {"ok": True}

    assert TestClient(app, raise_server_exceptions=False).post("/dup").status_code == 500


def test_library_routers_are_function_scoped(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    from flyfun_common.admin_hub import create_hub_router
    from flyfun_common.auth.router import create_auth_router
    from flyfun_common.autorouter import (
        create_autorouter_router,
        create_autorouter_routes_router,
    )
    from flyfun_common.oauth.router import create_oauth_router

    app = FastAPI()
    app.include_router(create_auth_router())
    app.include_router(create_oauth_router())
    app.include_router(create_hub_router(require_admin=lambda: None))
    app.include_router(create_autorouter_router())
    app.include_router(create_autorouter_routes_router())
    assert len(app.routes) > 20
    assert find_request_scoped_db(app) == []


def test_find_request_scoped_db_flags_bare_and_nested_get_db():
    app = FastAPI()

    def needs_db(db: Session = Depends(get_db)):
        return db

    @app.get("/bare")
    def bare(db: Session = Depends(get_db)):
        return {}

    @app.get("/nested")
    def nested(_=Depends(needs_db)):
        return {}

    @app.get("/scoped")
    def scoped(db: Session = Depends(get_db, scope="function")):
        return {}

    assert find_request_scoped_db(app) == ["GET /bare", "GET /nested"]
