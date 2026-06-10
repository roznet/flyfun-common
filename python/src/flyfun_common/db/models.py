"""Shared SQLAlchemy models: users, API tokens, preferences, cost ledger.

App-specific models (flights, briefings, usage, etc.) stay in each app.
Apps can add relationships to UserRow via SQLAlchemy backref or explicit
relationship() on their own models pointing to "users.id".
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), default="local")
    provider_sub: Mapped[str] = mapped_column(String(256), default="")
    email: Mapped[str] = mapped_column(String(256), default="")
    display_name: Mapped[str] = mapped_column(String(256), default="")
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # Session-epoch revocation: any JWT whose `iat` predates this timestamp is
    # rejected by `current_user_id`. Set on "log out everywhere" / suspected
    # compromise to kill all of a user's outstanding (and self-renewing) tokens
    # at once. NULL = never revoked (the common case; no UX impact).
    tokens_valid_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class ApiTokenRow(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    oauth_client_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None
    )


class UserPreferencesRow(Base):
    __tablename__ = "user_preferences"

    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    setup_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_creds_json: Mapped[str] = mapped_column(Text, default="")
    app_prefs_json: Mapped[str] = mapped_column(Text, default="{}")


class MagicLinkTokenRow(Base):
    __tablename__ = "magic_link_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(256), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    otp_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    requested_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None, index=True
    )
    # Failed-OTP counter. The token is burned (used_at set) once this reaches
    # MAX_OTP_ATTEMPTS, bounding brute force of the 6-digit code regardless of
    # per-IP rate limiting.
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )


class MagicLinkConsumeAttemptRow(Base):
    __tablename__ = "magic_link_consume_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class CostLedgerRow(Base):
    __tablename__ = "cost_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    service: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    cost: Mapped[float] = mapped_column(Float)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Extended columns for richer cost attribution (all nullable for backward compat)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    detail_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference_id: Mapped[str | None] = mapped_column(String(128), nullable=True)


class DonationRow(Base):
    """Voluntary donations (money *in*), kept separate from the cost ledger.

    Distinct from CostLedgerRow on purpose: donations carry a charged currency,
    a Stripe reference, and a refundable status — a different shape from the cost
    ledger's "always positive USD = cost" invariant. USD is the canonical
    accounting currency: ``amount``/``currency`` are what Stripe charged, and
    ``amount_usd`` is converted once at webhook time so historical totals don't
    drift with FX.

    The actual ``donation_ledger`` table is created by each consuming app's
    Alembic migration (flyfun-common ships no migrations of its own), the same
    way ``cost_ledger`` is.
    """

    __tablename__ = "donation_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Nullable, no FK: anonymous/logged-out donors are allowed, and an
    # attributed donation must survive deletion of the donor's user row.
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service: Mapped[str] = mapped_column(String(64))
    amount: Mapped[float] = mapped_column(Float)  # charged amount in `currency`, positive
    currency: Mapped[str] = mapped_column(String(3))  # ISO 4217 as charged
    amount_usd: Mapped[float] = mapped_column(Float)  # converted to USD at donation time
    fx_rate: Mapped[float] = mapped_column(Float)  # rate used, recorded for auditability
    # USD net of the Stripe fee, when known from the balance transaction.
    net_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    recurring: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="succeeded")
    provider: Mapped[str] = mapped_column(String(32), default="stripe")
    # Stripe PaymentIntent / Checkout Session id. Unique for webhook idempotency;
    # capped at 191 chars for MySQL utf8mb4 unique-index limits.
    provider_ref: Mapped[str] = mapped_column(String(191), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,  # yearly community rollups filter/sort on this
    )
