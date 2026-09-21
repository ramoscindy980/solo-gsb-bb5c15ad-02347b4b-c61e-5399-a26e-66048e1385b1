#!/usr/bin/env python3
"""Initialise the SQLite database (idempotent)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import get_settings  # noqa: E402
from app.db import init_db  # noqa: E402

if __name__ == "__main__":
    settings = get_settings()
    init_db(settings.database_path)
    print(f"database ready: {settings.database_path}")
