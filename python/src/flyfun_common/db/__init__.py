"""Database models and engine for shared user tables."""

from flyfun_common.db.models import (
    Base,
    UserRow,
    ApiTokenRow,
    UserPreferencesRow,
    CostLedgerRow,
    MagicLinkTokenRow,
    MagicLinkConsumeAttemptRow,
)
from flyfun_common.db.engine import (
    get_engine,
    reset_engine,
    init_shared_db,
    ensure_dev_user,
    find_orphaned_user_ids,
    SessionLocal,
    DEV_USER_ID,
)

# Lazy imports to avoid circular dependency (deps → auth.config → auth → router → deps)


def __getattr__(name: str):
    if name in (
        "get_db",
        "current_user_id",
        "optional_user_id",
        "register_scope_paths",
    ):
        from flyfun_common.db import deps

        return getattr(deps, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Base",
    "UserRow",
    "ApiTokenRow",
    "UserPreferencesRow",
    "CostLedgerRow",
    "MagicLinkTokenRow",
    "MagicLinkConsumeAttemptRow",
    "get_engine",
    "reset_engine",
    "init_shared_db",
    "ensure_dev_user",
    "find_orphaned_user_ids",
    "SessionLocal",
    "DEV_USER_ID",
    "get_db",
    "current_user_id",
    "optional_user_id",
    "register_scope_paths",
]
