"""Encryption of fragment mappings, placeholder digests and one-time tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet

_PBKDF2_SALT = b"contract-redaction/v1"
_PBKDF2_ROUNDS = 210_000


def _derive_fernet_key(secret: str) -> bytes:
    """Turn an arbitrary passphrase into a Fernet key (deterministic)."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), _PBKDF2_SALT, _PBKDF2_ROUNDS
    )
    return base64.urlsafe_b64encode(dk)


def _load_master_key(env_value: str | None, key_file: str) -> bytes:
    if env_value:
        candidate = env_value.strip().encode()
        try:
            if len(base64.urlsafe_b64decode(candidate)) == 32:
                return candidate  # already a Fernet-compatible key
        except Exception:
            pass
        return _derive_fernet_key(env_value)
    # No env secret: persist a generated key so restarts keep working (dev mode).
    path = Path(key_file)
    if path.exists():
        return path.read_text().strip().encode()
    key = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.decode())
    os.chmod(path, 0o600)
    return key


@dataclass(frozen=True)
class Crypto:
    fernet: Fernet
    hmac_key: bytes

    def encrypt(self, plaintext: str) -> bytes:
        return self.fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        return self.fernet.decrypt(bytes(ciphertext)).decode("utf-8")

    def placeholder_digest(
        self, doc_id: str, start: int, end: int, category: str
    ) -> str:
        """Deterministic 12-hex digest -> stable placeholder per fragment."""
        msg = f"{doc_id}:{start}:{end}:{category}".encode("utf-8")
        return hmac.new(self.hmac_key, msg, hashlib.sha256).hexdigest()[:12]


@lru_cache
def get_crypto() -> Crypto:
    from .config import get_settings

    settings = get_settings()
    master = _load_master_key(settings.master_key, settings.key_file)
    hmac_key = hmac.new(b"placeholder-ids", master, hashlib.sha256).digest()
    return Crypto(fernet=Fernet(master), hmac_key=hmac_key)


def reset_crypto_cache() -> None:
    get_crypto.cache_clear()


def new_restore_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
