# DB Module

> Shared SQLAlchemy models, engine singleton, and FastAPI dependencies

## Intent

Provide the shared database layer that all flyfun apps connect to. Contains only cross-app tables (`users`, `api_tokens`). App-specific tables (flights, briefings, usage, etc.) live in each app and reference `users.id` via foreign key.

## Architecture

```
db/
├── models.py    # UserRow, ApiTokenRow, Base (DeclarativeBase)
├── engine.py    # Singleton engine, init_shared_db, ensure_dev_user
└── deps.py      # get_db(), current_user_id() FastAPI dependencies
```

### Shared Tables

**`users`** — one row per person across all flyfun apps:

| Column | Type | Notes |
|--------|------|-------|
| `id` | String(64) PK | UUID |
| `provider` | String(32) | `google`, `local`, `api` |
| `provider_sub` | String(256) | OAuth subject ID |
| `email` | String(256) | From OAuth profile |
| `display_name` | String(256) | |
| `approved` | Boolean | Default True; admin can revoke |
| `credit_balance` | Float | Default 500.0 (for metered services) |
| `created_at` | DateTime(tz) | |
| `last_login_at` | DateTime(tz) | Nullable |

**`api_tokens`** — programmatic access tokens (CLI, automation):

| Column | Type | Notes |
|--------|------|-------|
| `id` | Integer PK | Auto-increment |
| `user_id` | String(64) | References users.id (no FK constraint in model) |
| `token_hash` | String(64) | SHA256 of `ff_...` token, unique+indexed |
| `name` | String(256) | User-assigned label |
| `expires_at` | DateTime(tz) | Nullable (no expiry if null) |
| `last_used_at` | DateTime(tz) | Updated on each use |
| `revoked` | Boolean | Soft revocation |

### No ORM Relationships on Shared Models

UserRow and ApiTokenRow deliberately have **no SQLAlchemy `relationship()` definitions**. This avoids coupling them to app-specific models. Each app adds its own relationships on its own models:

```python
# In flyfun-weather's models.py
class FlightRow(weather_Base):
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    user: Mapped[UserRow] = relationship()  # works because same DB
```

### Engine Singleton

- Dev: `sqlite:///{DATA_DIR}/flyfun.db` (WAL mode, foreign keys ON)
- Prod: `DATABASE_URL` env var (MySQL/PostgreSQL, pool_pre_ping not yet added)
- `SessionLocal` is configured when `get_engine()` is first called
- `reset_engine()` for testing

### App-Specific Tables

Each app has its own `Base` subclass for its tables. At startup:

```python
from flyfun_common.db import init_shared_db, get_engine
from myapp.db.models import AppBase

init_shared_db()                          # creates users, api_tokens
AppBase.metadata.create_all(get_engine()) # creates app-specific tables
```

Both sets of tables live in the same database.

## Usage Examples

```python
# App startup (e.g., in FastAPI lifespan)
from flyfun_common.db import init_shared_db, ensure_dev_user, SessionLocal

init_shared_db()
session = SessionLocal()
ensure_dev_user(session)
session.close()
```

```python
# FastAPI endpoint with auth
from flyfun_common.db import get_db, current_user_id

@app.post("/my-action")
def my_action(user_id: str = Depends(current_user_id), db=Depends(get_db)):
    # user_id is validated: exists in DB + approved
    db.add(MyAppModel(user_id=user_id, ...))
    # session auto-commits via get_db() generator
```

```python
# Query the shared user directly
from flyfun_common.db import UserRow

user = db.get(UserRow, user_id)
if user.credit_balance < cost:
    raise HTTPException(402, "Insufficient credits")
```

## Key Choices

- **No FK constraint on `api_tokens.user_id`**: The column is just `String(64)` with an index, not a `ForeignKey`. This avoids issues with table creation order when shared and app-specific tables use different `Base` classes. Referential integrity is enforced at the application level.
- **`credit_balance` on UserRow**: Kept from flyfun-weather. Apps that don't use credits simply ignore it. Avoids a separate table for a single float.
- **Single `flyfun.db` in dev**: All apps share one SQLite file locally. Simulates the shared MySQL in production.
- **`get_db()` auto-commits**: The generator commits on success, rolls back on exception. Endpoints don't need explicit `db.commit()`.

## Gotchas

- `get_engine()` is a **singleton** — once created, changing env vars has no effect. Use `reset_engine()` in tests.
- `init_shared_db()` calls `Base.metadata.create_all()` which only creates tables from `flyfun_common.db.models`. App tables need their own `create_all()` call.
- In dev mode, `current_user_id()` always returns `"dev-user-001"` without touching the DB.
- `SessionLocal` must be configured (via `get_engine()` or `init_shared_db()`) before `get_db()` is called.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `ENVIRONMENT` | No | `development` | Switches SQLite/MySQL |
| `DATABASE_URL` | Prod | — | MySQL/PostgreSQL connection string |
| `DATA_DIR` | No | `data` | SQLite file location (dev) |

## References

- Models: `src/flyfun_common/db/models.py`
- Engine: `src/flyfun_common/db/engine.py`
- Dependencies: `src/flyfun_common/db/deps.py`
- See [Auth design](./auth.md) for authentication flow
