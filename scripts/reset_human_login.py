"""One-time production human-login repair helper.

If UNG_IAM_RESET_SOURCE_EMAIL and UNG_IAM_RESET_EMAIL are set, the selected
human administrator can be renamed without changing its existing password.
If UNG_IAM_RESET_PASSWORD is also set, its password is reset. The identity is
re-enabled, platform-admin is guaranteed, and only its human sessions are
revoked. Service credentials are untouched.
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
    source_email = os.getenv("UNG_IAM_RESET_SOURCE_EMAIL", "").strip().lower()
    target_email = os.getenv("UNG_IAM_RESET_EMAIL", "").strip().lower()
    bootstrap_email = os.getenv("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
    source_email = source_email or target_email or bootstrap_email
    target_email = target_email or source_email

    if not password and source_email == target_email:
        print("IAM reset skipped: no one-time login repair configured")
        return
    if not source_email or not target_email:
        raise SystemExit("IAM source and target login emails are required")

    c = connect()
    try:
        row = c.execute("SELECT id,password_hash FROM identities WHERE email=? AND identity_type='human'", (source_email,)).fetchone()
        if not row:
            raise SystemExit("Requested administrator identity does not exist")
        identity_id = row["id"]
        conflict = c.execute("SELECT id FROM identities WHERE email=? AND id<>?", (target_email, identity_id)).fetchone()
        if conflict:
            raise SystemExit("Requested target login email is already in use")

        new_hash = password_hash(password) if password else row["password_hash"]
        if not new_hash:
            raise SystemExit("Selected administrator has no local password to preserve")
        c.execute(
            "UPDATE identities SET email=?, password_hash=?, is_active=1, updated_at=? WHERE id=?",
            (target_email, new_hash, time.time(), identity_id),
        )
        role = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
        if not role:
            raise SystemExit("platform-admin role is missing")
        c.execute("INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)", (identity_id, role["id"]))
        c.execute("DELETE FROM sessions WHERE identity_id=?", (identity_id,))
        c.commit()
        print("IAM administrator login repaired; human sessions revoked")
    finally:
        c.close()


if __name__ == "__main__":
    main()
