"""End-to-end API tests against a temporary SQLite database."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("REDACTION_MASTER_KEY", "test-master-key")
    monkeypatch.setenv("TOKEN_TTL_SECONDS", "3600")

    from app.config import reset_settings_cache
    from app.security import reset_crypto_cache

    reset_settings_cache()
    reset_crypto_cache()

    from app.main import app

    with TestClient(app) as c:
        yield c

    reset_settings_cache()
    reset_crypto_cache()


CONTRACT = "甲方张三（身份证号110101199001011234）与乙方北京示例科技有限公司签订合同"


def create_doc(client, **overrides):
    payload = {
        "text": CONTRACT,
        "fragments": [
            {"start": 2, "end": 4, "category": "name", "priority": 5},
            {"start": 5, "end": 23, "category": "id_number", "priority": 10},
            {"start": 20, "end": 26, "category": "id_tail", "priority": 1},  # overlaps, loses
            {"start": 26, "end": 38, "category": "company", "priority": 5},
        ],
    }
    payload.update(overrides)
    return client.post("/v1/redactions", json=payload)


def test_create_redaction_resolves_overlaps(client):
    resp = create_doc(client)
    assert resp.status_code == 201, resp.text
    body = resp.json()

    assert body["redacted_text"].count("[[") == 3
    assert "张三" not in body["redacted_text"]
    assert "110101199001011234" not in body["redacted_text"]
    assert "北京示例科技有限公司" not in body["redacted_text"]

    assert len(body["fragments"]) == 3
    assert len(body["dropped"]) == 1
    assert body["dropped"][0]["category"] == "ID_TAIL"
    assert body["dropped"][0]["reason"] == "overlap_higher_priority"

    # placeholders are stable: same document id + span -> same digest
    phs = [f["placeholder"] for f in body["fragments"]]
    assert all(p.startswith("[[") and p.endswith("]]") for p in phs)
    assert len(set(phs)) == 3

    # fragment positions refer to the original text
    for f in body["fragments"]:
        assert f["end"] > f["start"]
        assert f["redacted_end"] > f["redacted_start"]

    assert body["restore_token"]
    assert body["restore_token_expires_at"]


def test_out_of_bounds_fragment_rejected(client):
    resp = client.post(
        "/v1/redactions",
        json={"text": "abc", "fragments": [{"start": 1, "end": 9}]},
    )
    assert resp.status_code == 422


def test_get_redaction_returns_details_without_plaintext(client):
    doc = create_doc(client).json()
    resp = client.get(f"/v1/redactions/{doc['document_id']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["redacted_text"] == doc["redacted_text"]
    assert len(body["fragments"]) == 3
    assert all("text" not in f for f in body["fragments"])
    assert all(f["expired"] is False for f in body["fragments"])
    assert len(body["dropped"]) == 1


def test_get_unknown_document_404(client):
    assert client.get("/v1/redactions/doc_nope").status_code == 404


def test_restore_with_one_time_token(client):
    doc = create_doc(client).json()
    doc_id = doc["document_id"]
    name_ph = next(
        f["placeholder"] for f in doc["fragments"] if f["category"] == "NAME"
    )

    # wrong token -> 401
    bad = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": "wrong", "placeholders": [name_ph]},
    )
    assert bad.status_code == 401

    # unknown placeholder -> 404 (token not consumed)
    missing = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": doc["restore_token"], "placeholders": ["[[NOPE#000000000000]]"]},
    )
    assert missing.status_code == 404

    # restore only the requested placeholder
    ok = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": doc["restore_token"], "placeholders": [name_ph]},
    )
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert "张三" in body["restored_text"]
    assert "110101199001011234" not in body["restored_text"]  # others stay masked
    assert body["restored"] == [
        {"placeholder": name_ph, "category": "NAME", "text": "张三"}
    ]

    # token is single-use
    again = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": doc["restore_token"], "placeholders": [name_ph]},
    )
    assert again.status_code == 409


def test_restore_all_placeholders_recovers_original(client):
    doc = create_doc(client).json()
    resp = client.post(
        f"/v1/redactions/{doc['document_id']}/restore",
        json={
            "token": doc["restore_token"],
            "placeholders": [f["placeholder"] for f in doc["fragments"]],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["restored_text"] == CONTRACT


def test_expired_mapping_returns_410(client, tmp_path):
    doc = create_doc(client, mapping_ttl_seconds=3600).json()
    doc_id = doc["document_id"]
    ph = doc["fragments"][0]["placeholder"]

    # force the mapping into the past
    conn = sqlite3.connect(tmp_path / "test.db")
    conn.execute(
        "UPDATE mappings SET expires_at = '2000-01-01T00:00:00Z' WHERE placeholder = ?",
        (ph,),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": doc["restore_token"], "placeholders": [ph]},
    )
    assert resp.status_code == 410

    # token was not consumed by the failed restore
    conn = sqlite3.connect(tmp_path / "test.db")
    row = conn.execute(
        "SELECT used_at FROM restore_tokens WHERE document_id = ?", (doc_id,)
    ).fetchone()
    conn.close()
    assert row[0] is None


def test_expired_token_returns_410(client):
    doc = create_doc(client, token_ttl_seconds=1).json()
    doc_id = doc["document_id"]
    ph = doc["fragments"][0]["placeholder"]

    import time

    time.sleep(1.1)
    resp = client.post(
        f"/v1/redactions/{doc_id}/restore",
        json={"token": doc["restore_token"], "placeholders": [ph]},
    )
    assert resp.status_code == 410
