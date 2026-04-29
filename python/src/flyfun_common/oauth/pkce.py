"""PKCE (S256) verification for OAuth 2.1 authorization code flow."""

from __future__ import annotations

import hashlib
import hmac
import re
from base64 import urlsafe_b64encode

# RFC 7636 §4.1: verifier is 43-128 chars of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify a PKCE S256 code_verifier against the stored code_challenge.

    Returns True if the verifier is valid. Uses constant-time comparison.
    """
    if not _VERIFIER_RE.match(code_verifier):
        return False

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected, code_challenge)
