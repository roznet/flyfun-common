# flyfun-common

Shared user management and authentication library for [flyfun](https://flyfun.aero) services.

Provides OAuth login (Google, Apple), JWT session management, user database models, and API token administration — all as reusable FastAPI components.

## Installation

```bash
pip install flyfun-common
```

## Usage

```python
from fastapi import FastAPI
from flyfun_common.auth import create_auth_router
from flyfun_common.db import init_db

app = FastAPI()

# Initialize database
init_db()

# Mount the auth router
app.include_router(create_auth_router())
```

## Configuration

All configuration is via environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Production | Secret key for signing JWT tokens |
| `DATABASE_URL` | No | SQLAlchemy database URL (defaults to local SQLite) |
| `ENVIRONMENT` | No | `production` or `development` (default) |
| `COOKIE_DOMAIN` | No | Cookie domain for cross-subdomain SSO |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `APPLE_CLIENT_ID` | No | Apple Sign In service ID |
| `APPLE_TEAM_ID` | No | Apple Developer Team ID |
| `APPLE_KEY_ID` | No | Apple Sign In key ID |
| `APPLE_PRIVATE_KEY` | No | Apple Sign In private key (PEM) |
| `CREDENTIAL_ENCRYPTION_KEY` | Production | Fernet key for encrypting stored credentials |

## License

MIT
