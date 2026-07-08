from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet

API_KEY_PREFIX = "aa"


def generate_api_key() -> tuple[str, str, str]:
    """Returns (full_key, key_id, secret_hash). Full key shown to the user once."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    full_key = f"{API_KEY_PREFIX}_{key_id}_{secret}"
    return full_key, key_id, hash_secret(secret)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def parse_api_key(full_key: str) -> tuple[str, str] | None:
    """Returns (key_id, secret) or None if malformed."""
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX:
        return None
    return parts[1], parts[2]


def verify_secret(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash)


def generate_fernet_key() -> str:
    return Fernet.generate_key().decode()


class SecretBox:
    """Fernet wrapper for encrypting cached credentials at rest."""

    def __init__(self, key: str):
        self._fernet = Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()
