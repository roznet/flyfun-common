"""Tests for cost ledger utilities."""

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flyfun_common.db.models import Base, UserRow
from flyfun_common.costs import (
    check_budget,
    get_cost_breakdown,
    get_cost_since,
    get_total_cost,
    record_cost,
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(UserRow(id="u1", approved=True, spending_limit=100.0))
    session.flush()
    yield session
    session.close()
    engine.dispose()


def test_record_and_total(db):
    record_cost(db, "u1", "weather", "briefing", 0.05)
    record_cost(db, "u1", "weather", "gramet", 0.02)
    assert get_total_cost(db, "u1") == pytest.approx(0.07)
    assert get_total_cost(db, "u1", service="weather") == pytest.approx(0.07)


def test_cost_since(db):
    old = record_cost(db, "u1", "weather", "briefing", 1.0)
    old.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    db.flush()

    record_cost(db, "u1", "weather", "briefing", 2.0)
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    assert get_cost_since(db, "u1", since) == pytest.approx(2.0)


def test_check_budget(db):
    record_cost(db, "u1", "weather", "briefing", 50.0)
    spent, limit = check_budget(db, "u1")
    assert spent == pytest.approx(50.0)
    assert limit == pytest.approx(100.0)


def test_cost_breakdown(db):
    record_cost(db, "u1", "weather", "briefing", 0.05, metadata={"tokens": 100})
    record_cost(db, "u1", "weather", "gramet", 0.02)
    rows = get_cost_breakdown(db, "u1")
    assert len(rows) == 2
    assert rows[0].action == "gramet"  # newest first


def test_service_filter(db):
    record_cost(db, "u1", "weather", "briefing", 1.0)
    record_cost(db, "u1", "customs", "lookup", 0.5)
    assert get_total_cost(db, "u1", service="customs") == pytest.approx(0.5)
