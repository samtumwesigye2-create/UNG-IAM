"""One-time production human-login reset helper.

Runs only when UNG_IAM_RESET_PASSWORD is present. It resets the configured
bootstrap administrator password, re-enables the identity, guarantees the
platform-admin role, and revokes only that human identity's sessions. Service
credentials are deliberately untouched.
"""
import hashlib
import os
import secrets
import time

from db import connect


def password_hash(password: str) -> str:
    if len(password) < 12:
        raise SystemExit("UNG_IAM_RESET_PASSWORD must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def main() -> None:
    password = os.getenv("UNG_IAM_RESET_PASSWORD", "")
    email = os.getenv("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
    if not password:
        print("IAM reset skipped: no one-time reset password configured")
        return
    if not email:
        raise SystemExit("UNG_IAM_BOOTSTRAP_EMAIL is required for reset")

    c = connect()
    try:
        row = c.execute("SELECT id FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
        if not row:
            raise SystemExit("Configured bootstrap administrator identity does not exist")
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
        print("IAM bootstrap administrator password reset; human sessions revoked")
    finally:
        c.close()


if __name__ == "__main__":
    main()
