"""Cross-app admin hub: user cost overview across all flyfun services."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, func
from sqlalchemy.orm import Session

from flyfun_common.db import get_db
from flyfun_common.db.models import CostLedgerRow, UserRow


def create_hub_router(
    require_admin: Callable,
    app_registry: dict[str, str | None] | None = None,
) -> APIRouter:
    """Create a mountable admin hub router.

    Args:
        require_admin: FastAPI dependency that validates admin access.
        app_registry: Map of service name to detail URL template.
            Use ``{user_id}`` placeholder.  ``None`` value means no detail page.
    """
    router = APIRouter(prefix="/hub", tags=["admin-hub"])
    registry = app_registry or {}

    @router.get("/users")
    def get_hub_users(
        period: str = Query("30d", pattern="^(30d|all)$"),
        _admin_id: str = Depends(require_admin),
        db: Session = Depends(get_db),
    ):
        since = None
        if period == "30d":
            since = datetime.now(timezone.utc) - timedelta(days=30)

        # --- Per-user, per-service aggregates ---
        q = (
            db.query(
                CostLedgerRow.user_id,
                CostLedgerRow.service,
                func.sum(CostLedgerRow.cost).label("cost_usd"),
                func.count().label("action_count"),
            )
            .filter(CostLedgerRow.cost > 0)  # exclude topups
        )
        if since:
            q = q.filter(CostLedgerRow.created_at >= since)
        rows = q.group_by(CostLedgerRow.user_id, CostLedgerRow.service).all()

        # Build per-user map
        user_map: dict[str, dict] = {}
        for user_id, service, cost_usd, count in rows:
            if user_id not in user_map:
                user_map[user_id] = {"services": {}, "total_cost_usd": 0.0, "total_actions": 0}
            user_map[user_id]["services"][service] = {
                "cost_usd": round(float(cost_usd), 4),
                "count": int(count),
            }
            user_map[user_id]["total_cost_usd"] += float(cost_usd)
            user_map[user_id]["total_actions"] += int(count)

        # Fetch user details for all users with cost data
        user_ids = list(user_map.keys())
        if user_ids:
            users = db.query(UserRow).filter(UserRow.id.in_(user_ids)).all()
        else:
            users = []
        user_info = {u.id: u for u in users}

        # Build response
        result_users = []
        for uid, data in sorted(user_map.items(), key=lambda x: x[1]["total_cost_usd"], reverse=True):
            u = user_info.get(uid)
            result_users.append({
                "id": uid,
                "email": u.email if u else "",
                "display_name": u.display_name if u else uid[:8],
                "approved": u.approved if u else False,
                "services": data["services"],
                "total_cost_usd": round(data["total_cost_usd"], 4),
                "total_actions": data["total_actions"],
            })

        total_cost = sum(u["total_cost_usd"] for u in result_users)
        total_actions = sum(u["total_actions"] for u in result_users)

        return {
            "period": period,
            "app_registry": registry,
            "users": result_users,
            "totals": {
                "cost_usd": round(total_cost, 4),
                "actions": total_actions,
                "users": len(result_users),
            },
        }

    return router
