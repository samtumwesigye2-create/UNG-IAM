"""One-time production human-login reset helper.

Runs only when UNG_IAM_RESET_PASSWORD is present. It resets the configured
bootstrap administrator password, can assign a new explicit login email,
re-enables the identity, guarantees platform-admin, and revokes only that
human identity's sessions. Service credentials are deliberately untouched.
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
    current_email = os.getenv("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
    new_email = os.getenv("UNG_IAM_RESET_EMAIL", "").strip().lower() or current_email
    if not password:
        print("IAM reset skipped: no one-time reset password configured")
        return
    if not current_email:
        raise SystemExit("UNG_IAM_BOOTSTRAP_EMAIL is required for reset")
    if not new_email:
        raise SystemExit("A reset login email is required")

    c = connect()
    try:
        row = c.execute("SELECT id FROM identities WHERE email=? AND identity_type='human'", (current_email,)).fetchone()
        if not row and new_email != current_email:
            row = c.execute("SELECT id FROM identities WHERE email=? AND identity_type='human'", (new_email,)).fetchone()
        if not row:
            raise SystemExit("Configured bootstrap administrator identity does not exist")
        identity_id = row["id"]
        conflict = c.execute("SELECT id FROM identities WHERE email=? AND id<>?", (new_email, identity_id)).fetchone()
        if conflict:
            raise SystemExit("Requested reset login email is already in use")
        c.execute(
            "UPDATE identities SET email=?, password_hash=?, is_active=1, updated_at=? WHERE id=?",
            (new_email, password_hash(password), time.time(), identity_id),
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
