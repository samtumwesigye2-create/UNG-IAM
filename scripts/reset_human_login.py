"""One-time production human-login reset helper.

Runs only when UNG_IAM_RESET_PASSWORD is present. When UNG_IAM_RESET_EMAIL is
set, that existing human identity is reset directly; otherwise the configured
bootstrap administrator is used. The identity is re-enabled, platform-admin is
guaranteed, and only its human sessions are revoked. Service credentials are
untouched.
"""
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db import connect


def password_hash(password: str) -> str:
    if len(password) < 12:
        raise SystemExit("UNG_IAM_RESET_PASSWORD must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def main() -> None:
    password = os.getenv("UNG_IAM_RESET_PASSWORD", "")
    explicit_email = os.getenv("UNG_IAM_RESET_EMAIL", "").strip().lower()
    bootstrap_email = os.getenv("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
    email = explicit_email or bootstrap_email
    if not password:
        print("IAM reset skipped: no one-time reset password configured")
        return
    if not email:
        raise SystemExit("An IAM reset or bootstrap email is required")

    c = connect()
    try:
        row = c.execute("SELECT id FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
        if not row:
            raise SystemExit("Requested administrator identity does not exist")
        identity_id = row["id"]
        c.execute(
            "UPDATE identities SET password_hash=?, is_active=1, updated_at=? WHERE id=?",
            (password_hash(password), time.time(), identity_id),
        )
        role = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if not role:
            raise SystemExit("platform-admin role is missing")
        c.execute("INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)", (identity_id, role["id"]))
        c.execute("DELETE FROM sessions WHERE identity_id=?", (identity_id,))
        c.commit()
        print("IAM administrator login reset; human sessions revoked")
    finally:
        c.close()


if __name__ == "__main__":
    main()
