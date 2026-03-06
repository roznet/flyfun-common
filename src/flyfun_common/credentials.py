"""Encrypted credential storage helpers using UserPreferencesRow."""

from __future__ import annotations

import json
import logging

from sqlalchemy.orm import Session

from flyfun_common.db.models import UserPreferencesRow
from flyfun_common.encryption import decrypt, encrypt

logger = logging.getLogger(__name__)


def save_encrypted_creds(db: Session, user_id: str, creds_dict: dict) -> None:
    """Encrypt and save credentials to UserPreferencesRow.encrypted_creds_json."""
    row = db.get(UserPreferencesRow, user_id)
    if row is None:
        row = UserPreferencesRow(user_id=user_id)
        db.add(row)
    row.encrypted_creds_json = encrypt(json.dumps(creds_dict))
    db.flush()


def load_encrypted_creds(db: Session, user_id: str) -> dict | None:
    """Load and decrypt credentials from UserPreferencesRow.

    Returns the decrypted dict, or None if not configured.
    """
    row = db.get(UserPreferencesRow, user_id)
    if not row or not row.encrypted_creds_json:
        return None
    try:
        return json.loads(decrypt(row.encrypted_creds_json))
    except Exception:
        logger.warning("Failed to decrypt credentials for user %s", user_id)
        return None


def clear_encrypted_creds(db: Session, user_id: str) -> None:
    """Clear stored credentials for a user."""
    row = db.get(UserPreferencesRow, user_id)
    if row:
        row.encrypted_creds_json = ""
        db.flush()
