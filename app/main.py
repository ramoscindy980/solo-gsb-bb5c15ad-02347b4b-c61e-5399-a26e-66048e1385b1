"""Contract text redaction API."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import InvalidToken
from fastapi import Depends, FastAPI, HTTPException

from . import db
from .config import get_settings
from .redact import (
    Fragment,
    build_redacted,
    normalize_category,
    resolve_overlaps,
    validate_fragments,
)
from .schemas import (
    DroppedDetail,
    FragmentDetail,
    RedactionQueryResponse,
    RedactionRequest,
    RedactionResponse,
    RestoreRequest,
    RestoreResponse,
    RestoredItem,
)
from .security import get_crypto, hash_token, new_restore_token


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _expiry(now: datetime, ttl_seconds: int | None) -> str | None:
    if ttl_seconds is None:
        return None
    return _iso(now + timedelta(seconds=ttl_seconds))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    db.init_db(settings.database_path)
    get_crypto()  # fail fast if the master key is unusable
    yield


app = FastAPI(
    title="Contract Redaction API",
    version="1.0.0",
    lifespan=lifespan,
)


def get_db():
    settings = get_settings()
    conn = db.connect(settings.database_path)
    try:
        yield conn
    finally:
        conn.close()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/redactions", response_model=RedactionResponse, status_code=201)
def create_redaction(req: RedactionRequest, conn: sqlite3.Connection = Depends(get_db)):
    settings = get_settings()
    crypto = get_crypto()
    text = req.text

    fragments = [
        Fragment(
            start=f.start,
            end=f.end,
            category=normalize_category(f.category),
            priority=f.priority,
        )
        for f in req.fragments
    ]
    errors = validate_fragments(len(text), fragments)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "fragment positions out of bounds", "errors": errors},
        )

    accepted, dropped = resolve_overlaps(fragments)

    doc_id = f"doc_{uuid.uuid4().hex}"
    now = _utcnow()

    def placeholder_fn(f: Fragment) -> str:
        digest = crypto.placeholder_digest(doc_id, f.start, f.end, f.category)
        return f"[[{f.category}#{digest}]]"

    redacted_text, placed = build_redacted(text, accepted, placeholder_fn)

    mapping_ttl = (
        req.mapping_ttl_seconds
        if req.mapping_ttl_seconds is not None
        else settings.default_mapping_ttl_seconds
    )
    mapping_expires = _expiry(now, mapping_ttl)
    token_ttl = (
        req.token_ttl_seconds
        if req.token_ttl_seconds is not None
        else settings.token_ttl_seconds
    )
    token_expires = _expiry(now, token_ttl)

    restore_token = new_restore_token()
    dropped_payload = [
        {
            "start": d.fragment.start,
            "end": d.fragment.end,
            "category": d.fragment.category,
            "priority": d.fragment.priority,
            "reason": d.reason,
        }
        for d in dropped
    ]

    with conn:  # single transaction: document + mappings + token
        conn.execute(
            "INSERT INTO documents (id, created_at, redacted_text, text_length,"
            " accepted_count, dropped_json) VALUES (?,?,?,?,?,?)",
            (
                doc_id,
                _iso(now),
                redacted_text,
                len(text),
                len(placed),
                json.dumps(dropped_payload, ensure_ascii=False),
            ),
        )
        conn.executemany(
            "INSERT INTO mappings (document_id, placeholder, category, start, \"end\","
            " priority, redacted_start, redacted_end, ciphertext, expires_at,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    doc_id,
                    p.placeholder,
                    p.fragment.category,
                    p.fragment.start,
                    p.fragment.end,
                    p.fragment.priority,
                    p.redacted_start,
                    p.redacted_end,
                    crypto.encrypt(text[p.fragment.start : p.fragment.end]),
                    mapping_expires,
                    _iso(now),
                )
                for p in placed
            ],
        )
        conn.execute(
            "INSERT INTO restore_tokens (token_hash, document_id, created_at,"
            " expires_at, used_at) VALUES (?,?,?,?,NULL)",
            (hash_token(restore_token), doc_id, _iso(now), token_expires),
        )

    return RedactionResponse(
        document_id=doc_id,
        created_at=_iso(now),
        redacted_text=redacted_text,
        fragments=[
            FragmentDetail(
                placeholder=p.placeholder,
                category=p.fragment.category,
                start=p.fragment.start,
                end=p.fragment.end,
                redacted_start=p.redacted_start,
                redacted_end=p.redacted_end,
                priority=p.fragment.priority,
                expires_at=mapping_expires,
                expired=False,
            )
            for p in placed
        ],
        dropped=[DroppedDetail(**d) for d in dropped_payload],
        restore_token=restore_token,
        restore_token_expires_at=token_expires,
    )


@app.get("/v1/redactions/{document_id}", response_model=RedactionQueryResponse)
def get_redaction(document_id: str, conn: sqlite3.Connection = Depends(get_db)):
    doc = conn.execute(
        "SELECT * FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if doc is None:
        raise HTTPException(status_code=404, detail="document not found")

    now = _utcnow()
    rows = conn.execute(
        "SELECT * FROM mappings WHERE document_id = ? ORDER BY redacted_start",
        (document_id,),
    ).fetchall()
    fragments = [
        FragmentDetail(
            placeholder=r["placeholder"],
            category=r["category"],
            start=r["start"],
            end=r["end"],
            redacted_start=r["redacted_start"],
            redacted_end=r["redacted_end"],
            priority=r["priority"],
            expires_at=r["expires_at"],
            expired=bool(r["expires_at"] and _parse(r["expires_at"]) <= now),
        )
        for r in rows
    ]
    return RedactionQueryResponse(
        document_id=doc["id"],
        created_at=doc["created_at"],
        redacted_text=doc["redacted_text"],
        fragments=fragments,
        dropped=[DroppedDetail(**d) for d in json.loads(doc["dropped_json"])],
    )


@app.post(
    "/v1/redactions/{document_id}/restore", response_model=RestoreResponse
)
def restore_redaction(
    document_id: str,
    req: RestoreRequest,
    conn: sqlite3.Connection = Depends(get_db),
):
    doc = conn.execute(
        "SELECT * FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if doc is None:
        raise HTTPException(status_code=404, detail="document not found")

    now = _utcnow()
    token_hash = hash_token(req.token)
    token = conn.execute(
        "SELECT * FROM restore_tokens WHERE token_hash = ? AND document_id = ?",
        (token_hash, document_id),
    ).fetchone()
    if token is None:
        raise HTTPException(status_code=401, detail="invalid restore token")
    if token["used_at"] is not None:
        raise HTTPException(status_code=409, detail="restore token already used")
    if token["expires_at"] and _parse(token["expires_at"]) <= now:
        raise HTTPException(status_code=410, detail="restore token expired")

    # de-duplicate while preserving order
    requested = list(dict.fromkeys(req.placeholders))
    marks = ",".join("?" for _ in requested)
    rows = conn.execute(
        f"SELECT * FROM mappings WHERE document_id = ? AND placeholder IN ({marks})",
        (document_id, *requested),
    ).fetchall()
    found = {r["placeholder"]: r for r in rows}
    missing = [p for p in requested if p not in found]
    if missing:
        raise HTTPException(
            status_code=404, detail={"unknown_placeholders": missing}
        )
    expired = [
        p
        for p in requested
        if found[p]["expires_at"] and _parse(found[p]["expires_at"]) <= now
    ]
    if expired:
        raise HTTPException(
            status_code=410, detail={"expired_placeholders": expired}
        )

    # Decrypt before consuming the token: a key mismatch must not burn it.
    crypto = get_crypto()
    try:
        plaintexts = {p: crypto.decrypt(found[p]["ciphertext"]) for p in requested}
    except InvalidToken:
        raise HTTPException(
            status_code=500,
            detail="mapping cannot be decrypted (master key mismatch)",
        )

    # Atomic one-time consumption (single UPDATE is a race-safe guard).
    cur = conn.execute(
        "UPDATE restore_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
        (_iso(now), token_hash),
    )
    if cur.rowcount != 1:
        raise HTTPException(status_code=409, detail="restore token already used")
    conn.commit()

    restored_text = doc["redacted_text"]
    for p in requested:
        restored_text = restored_text.replace(p, plaintexts[p])

    return RestoreResponse(
        document_id=document_id,
        restored_text=restored_text,
        restored=[
            RestoredItem(
                placeholder=p,
                category=found[p]["category"],
                text=plaintexts[p],
            )
            for p in requested
        ],
    )
