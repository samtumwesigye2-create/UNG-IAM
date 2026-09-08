"""Reconcile the configured JANUS bootstrap administrator.

Runs before application startup in production. It never prints credentials.
The Railway bootstrap secret remains the source of truth for emergency admin
recovery; normal IAM users and service credentials are untouched.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid

from db import connect


def password_hash(password: str) -> str:
    if len(password) < 12:
        raise RuntimeError("UNG_IAM_BOOTSTRAP_PASSWORD must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def main() -> None:
    email = os.environ.get("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
    password = os.environ.get("UNG_IAM_BOOTSTRAP_PASSWORD", "")
    if not email or not password:
        raise RuntimeError("JANUS bootstrap email/password are not configured")

    c = connect()
    try:
        role = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if not role:
            raise RuntimeError("platform-admin role is missing; IAM schema must initialize first")

        row = c.execute("SELECT id FROM identities WHERE email=?", (email,)).fetchone()
        ts = time.time()
        encoded = password_hash(password)
        if row:
            iid = row["id"]
            c.execute(
                "UPDATE identities SET identity_type='human', access_class='corporate', "
                "display_name='UNG IAM Bootstrap Administrator', password_hash=?, is_active=1, updated_at=? "
                "WHERE id=?",
                (encoded, ts, iid),
            )
        else:
            iid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO identities(id,identity_type,access_class,display_name,email,password_hash,is_active,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,1,?,?)",
                (iid, "human", "corporate", "UNG IAM Bootstrap Administrator", email, encoded, ts, ts),
            )

        c.execute("INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)", (iid, role["id"]))
        c.execute("DELETE FROM sessions WHERE identity_id=?", (iid,))
        c.commit()
        print("JANUS bootstrap administrator reconciled successfully")
    finally:
        c.close()


if __name__ == "__main__":
    main()
