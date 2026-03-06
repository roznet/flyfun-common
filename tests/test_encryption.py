"""Tests for Fernet encryption module."""

import os

import pytest


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("JWT_SECRET", raising=False)


def test_encrypt_decrypt_roundtrip():
    from flyfun_common.encryption import decrypt, encrypt

    plaintext = "hello world"
    ciphertext = encrypt(plaintext)
    assert ciphertext != plaintext
    assert decrypt(ciphertext) == plaintext


def test_encrypt_produces_different_tokens():
    from flyfun_common.encryption import encrypt

    a = encrypt("same")
    b = encrypt("same")
    # Fernet tokens include a timestamp, so they differ
    assert a != b


def test_explicit_key(monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", key)

    from flyfun_common.encryption import decrypt, encrypt

    ct = encrypt("secret")
    assert decrypt(ct) == "secret"


def test_production_requires_key(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("JWT_SECRET", "prod-secret-value")

    from flyfun_common.encryption import encrypt

    with pytest.raises(ValueError, match="CREDENTIAL_ENCRYPTION_KEY"):
        encrypt("test")
