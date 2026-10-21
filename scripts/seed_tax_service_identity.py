#!/usr/bin/env python3
"""Idempotently seed the dedicated UNG-TAX JANUS service principal.

The principal id is deterministic so migrations and audit records can refer to
it without querying or exposing a human administrator identity. The raw
credential is supplied by deployment secrets; JANUS stores only its SHA-256
hash.
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db import connect

TAX_SERVICE_PRINCIPAL_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:ung:service:tax"))
DISPLAY_NAME = "UNG-TAX"
CREDENTIAL_LABEL = "UNG-TAX-PRODUCTION"


def seed_tax_service_identity(conn, raw_credential: str) -> str:
    raw_credential = (raw_credential or "").strip()
    if len(raw_credential) < 32:
        raise RuntimeError("UNG_IAM_TAX_SERVICE_TOKEN must be at least 32 characters")

    conflict = conn.execute(
        "SELECT id FROM identities WHERE identity_type='service' AND display_name=? AND id<>?",
        (DISPLAY_NAME, TAX_SERVICE_PRINCIPAL_ID),
    ).fetchone()
    if conflict:
        raise RuntimeError(
            f"existing UNG-TAX service identity uses unexpected principal id {conflict['id']}"
        )

    now = time.time()
    row = conn.execute("SELECT id FROM identities WHERE id=?", (TAX_SERVICE_PRINCIPAL_ID,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO identities(id,identity_type,access_class,display_name,email,password_hash,is_active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",
            (TAX_SERVICE_PRINCIPAL_ID, "service", "service", DISPLAY_NAME, None, None, now, now),
        )
    else:
        conn.execute(
            "UPDATE identities SET identity_type='service',access_class='service',display_name=?,is_active=1,updated_at=? WHERE id=?",
            (DISPLAY_NAME, now, TAX_SERVICE_PRINCIPAL_ID),
        )

    role = conn.execute("SELECT id FROM roles WHERE name='service'").fetchone()
    if not role:
        raise RuntimeError("JANUS service role is missing")
    conn.execute(
        "INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)",
        (TAX_SERVICE_PRINCIPAL_ID, role["id"]),
    )
    conn.execute(
        "INSERT OR IGNORE INTO service_credentials(credential_hash,identity_id,label,expires_at,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)",
        (
            hashlib.sha256(raw_credential.encode()).hexdigest(),
            TAX_SERVICE_PRINCIPAL_ID,
            CREDENTIAL_LABEL,
            None,
            now,
        ),
    )
    conn.commit()
    return TAX_SERVICE_PRINCIPAL_ID


def main() -> int:
    raw = os.environ.get("UNG_IAM_TAX_SERVICE_TOKEN", "")
    conn = connect()
    try:
        principal_id = seed_tax_service_identity(conn, raw)
    finally:
        conn.close()
    print(f"UNG-TAX JANUS principal ready: {principal_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
