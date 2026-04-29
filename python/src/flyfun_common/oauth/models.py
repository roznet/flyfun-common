"""OAuth 2.1 models: clients, authorization codes, refresh tokens."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from flyfun_common.db.models import Base


class OAuthClientRow(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_secret_hash: Mapped[str] = mapped_column(String(64))
    client_name: Mapped[str] = mapped_column(String(256), default="")
    redirect_uris_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class OAuthAuthorizationCodeRow(Base):
    __tablename__ = "oauth_authorization_codes"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    redirect_uri: Mapped[str] = mapped_column(String(1024))
    code_challenge: Mapped[str] = mapped_column(String(128))
    scope: Mapped[str] = mapped_column(String(256), default="mcp")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    # Set when tokens are issued — enables revocation on auth code replay
    access_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None
    )


class OAuthRefreshTokenRow(Base):
    __tablename__ = "oauth_refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    access_token_hash: Mapped[str] = mapped_column(String(64))
    scope: Mapped[str] = mapped_column(String(256), default="mcp")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
