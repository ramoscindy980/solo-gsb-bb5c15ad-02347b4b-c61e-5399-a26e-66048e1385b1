"""Application settings, sourced from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: str
    database_path: str
    master_key: str | None          # raw env secret (Fernet key or passphrase)
    key_file: str                   # fallback location for a generated key
    token_ttl_seconds: int          # lifetime of one-time restore tokens
    default_mapping_ttl_seconds: int | None  # default mapping expiry (None = never)


@lru_cache
def get_settings() -> Settings:
    data_dir = os.environ.get("DATA_DIR", "./data")
    mapping_ttl = os.environ.get("MAPPING_TTL_SECONDS")
    return Settings(
        data_dir=data_dir,
        database_path=os.environ.get(
            "DATABASE_PATH", str(Path(data_dir) / "redaction.db")
        ),
        master_key=os.environ.get("REDACTION_MASTER_KEY") or None,
        key_file=os.environ.get(
            "REDACTION_KEY_FILE", str(Path(data_dir) / ".master_key")
        ),
        token_ttl_seconds=int(os.environ.get("TOKEN_TTL_SECONDS", "86400")),
        default_mapping_ttl_seconds=int(mapping_ttl) if mapping_ttl else None,
    )


def reset_settings_cache() -> None:
    """Used by tests to pick up changed environment variables."""
    get_settings.cache_clear()
