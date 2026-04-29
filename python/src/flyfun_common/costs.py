"""Cost ledger utilities: record, query, and check budget."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from flyfun_common.db.models import CostLedgerRow, UserRow


def record_cost(
    db: Session,
    user_id: str,
    service: str,
    action: str,
    cost: float,
    metadata: dict | None = None,
    *,
    category: str | None = None,
    description: str | None = None,
    detail_json: str | None = None,
    reference_id: str | None = None,
) -> CostLedgerRow:
    """Record a cost entry in the ledger."""
    row = CostLedgerRow(
        user_id=user_id,
        service=service,
        action=action,
        cost=cost,
        metadata_json=json.dumps(metadata) if metadata else None,
        category=category,
        description=description,
        detail_json=detail_json,
        reference_id=reference_id,
    )
    db.add(row)
    db.flush()
    return row


def get_total_cost(db: Session, user_id: str, service: str | None = None) -> float:
    """Sum of all costs for a user, optionally filtered by service."""
    q = db.query(func.coalesce(func.sum(CostLedgerRow.cost), 0.0)).filter(
        CostLedgerRow.user_id == user_id
    )
    if service:
        q = q.filter(CostLedgerRow.service == service)
    return float(q.scalar())


def get_cost_since(
    db: Session, user_id: str, since: datetime, service: str | None = None
) -> float:
    """Sum of costs since a given time."""
    q = db.query(func.coalesce(func.sum(CostLedgerRow.cost), 0.0)).filter(
        CostLedgerRow.user_id == user_id,
        CostLedgerRow.created_at >= since,
    )
    if service:
        q = q.filter(CostLedgerRow.service == service)
    return float(q.scalar())


def check_budget(db: Session, user_id: str) -> tuple[float, float]:
    """Return (total_spent, spending_limit) for a user."""
    total = get_total_cost(db, user_id)
    user = db.get(UserRow, user_id)
    limit = user.spending_limit if user else 500.0
    return total, limit


def get_cost_breakdown(
    db: Session,
    user_id: str,
    service: str | None = None,
    since: datetime | None = None,
    limit: int = 50,
) -> list[CostLedgerRow]:
    """Return recent cost entries for a user."""
    q = db.query(CostLedgerRow).filter(CostLedgerRow.user_id == user_id)
    if service:
        q = q.filter(CostLedgerRow.service == service)
    if since:
        q = q.filter(CostLedgerRow.created_at >= since)
    return q.order_by(CostLedgerRow.created_at.desc()).limit(limit).all()
