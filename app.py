"""UNG IAM — standalone Identity & Access Management platform.

Production persistence uses the dedicated PostgreSQL service exposed through
UNG_IAM_DATABASE_URL. SQLite remains a local-development fallback only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import struct
import time
import uuid
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db import connect, database_name, is_postgres

SESSION_TTL = max(300, int(os.environ.get("UNG_IAM_SESSION_TTL", "28800")))
SCIF_HANDLE_TTL = max(60, min(900, int(os.environ.get("UNG_IAM_SCIF_HANDLE_TTL", "300"))))
BOOTSTRAP_EMAIL = os.environ.get("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.environ.get("UNG_IAM_BOOTSTRAP_PASSWORD", "")
MFA_KEY_B64 = os.environ.get("UNG_IAM_MFA_KEY_B64", "").strip()

app = FastAPI(
    title="UNG IAM",
    description="Uganda National Grid Identity & Access Management",
    version="1.1.0",
)


def now() -> float:
    return time.time()


def db():
    return connect()


def password_hash(password: str, salt: Optional[bytes] = None) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def password_valid(password: str, encoded: str) -> bool:
    try:
        kind, n, r, p, salt_hex, digest_hex = encoded.split("$", 5)
        if kind != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def audit(event: str, actor_id: str = "", target_id: str = "", detail: str = ""):
    try:
        c = db()
        c.execute(
            "INSERT INTO audit_events(id,event,actor_id,target_id,detail,created_at) VALUES(?,?,?,?,?,?)",
            (str(uuid.uuid4()), event, actor_id, target_id, detail[:1200], now()),
        )
        c.commit()
        c.close()
    except Exception:
        pass


def init_db():
    c = db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS identities(
          id TEXT PRIMARY KEY,
          identity_type TEXT NOT NULL CHECK(identity_type IN ('human','service')),
          access_class TEXT NOT NULL CHECK(access_class IN ('corporate','vendor','contractor','service')),
          display_name TEXT NOT NULL,
          email TEXT UNIQUE,
          password_hash TEXT,
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roles(
          id TEXT PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permissions(
          name TEXT PRIMARY KEY,
          description TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS role_permissions(
          role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
          permission_name TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,
          PRIMARY KEY(role_id,permission_name)
        );
        CREATE TABLE IF NOT EXISTS identity_roles(
          identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
          role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
          PRIMARY KEY(identity_id,role_id)
        );
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY,
          identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
          expires_at REAL NOT NULL,
          created_at REAL NOT NULL,
          last_seen_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS service_credentials(
          credential_hash TEXT PRIMARY KEY,
          identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
          label TEXT NOT NULL,
          expires_at REAL,
          created_at REAL NOT NULL,
          last_used_at REAL
        );
        CREATE TABLE IF NOT EXISTS audit_events(
          id TEXT PRIMARY KEY,
          event TEXT NOT NULL,
          actor_id TEXT,
          target_id TEXT,
          detail TEXT,
          created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_codes(
          code_hash TEXT PRIMARY KEY,
          identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
          expires_at REAL NOT NULL,
          used_at REAL,
          created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mfa_factors(
          identity_id TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
          secret TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 0,
          created_at REAL NOT NULL,
          confirmed_at REAL
        );
        CREATE TABLE IF NOT EXISTS session_mfa(
          token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
          mfa_time REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scif_handles(
          handle_hash TEXT PRIMARY KEY,
          identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
          parent_token_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
          expires_at REAL NOT NULL,
          created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions(identity_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
        """
    )

    seed_permissions = {
        "iam:read": "Read identity and access configuration",
        "iam:write": "Create and update identities",
        "iam:roles": "Manage roles and permissions",
        "iam:audit": "Read IAM audit events",
        "iam:revoke": "Revoke sessions and credentials",
        "platform:corporate": "Access corporate-only systems",
        "platform:vendor": "Access approved vendor systems",
        "platform:contractor": "Access approved contractor systems",
        "platform:service": "System-to-system access",
    }
    for name, desc in seed_permissions.items():
        c.execute("INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)", (name, desc))

    roles = {
        "platform-admin": ("Full IAM administration", list(seed_permissions)),
        "security-admin": ("Security/access administration", ["iam:read", "iam:roles", "iam:audit", "iam:revoke"]),
        "corporate-user": ("Corporate workforce access", ["platform:corporate"]),
        "vendor": ("Approved vendor access", ["platform:vendor"]),
        "contractor": ("Approved contractor access", ["platform:contractor"]),
        "service": ("Machine identity", ["platform:service"]),
    }
    for role_name, (desc, perms) in roles.items():
        row = c.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
        rid = row["id"] if row else str(uuid.uuid4())
        if not row:
            c.execute("INSERT INTO roles(id,name,description,created_at) VALUES(?,?,?,?)", (rid, role_name, desc, now()))
        for perm in perms:
            c.execute("INSERT OR IGNORE INTO role_permissions(role_id,permission_name) VALUES(?,?)", (rid, perm))

    if BOOTSTRAP_EMAIL and BOOTSTRAP_PASSWORD:
        existing = c.execute("SELECT id FROM identities WHERE email=?", (BOOTSTRAP_EMAIL,)).fetchone()
        if not existing:
            iid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
                (iid, "human", "corporate", "UNG IAM Bootstrap Administrator", BOOTSTRAP_EMAIL,
                 password_hash(BOOTSTRAP_PASSWORD), now(), now()),
            )
            rid = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()["id"]
            c.execute("INSERT INTO identity_roles(identity_id,role_id) VALUES(?,?)", (iid, rid))
    # Controlled one-shot administrator recovery from deployment secrets.
    reset_password = os.environ.get("UNG_IAM_RESET_PASSWORD", "")
    reset_email = os.environ.get("UNG_IAM_RESET_EMAIL", "").strip().lower()
    reset_source_email = os.environ.get("UNG_IAM_RESET_SOURCE_EMAIL", "").strip().lower()
    recovery_target = reset_source_email or reset_email or BOOTSTRAP_EMAIL
    if reset_password and recovery_target:
        target = c.execute("SELECT id,email FROM identities WHERE email=? AND identity_type='human'", (recovery_target,)).fetchone()
        if target:
            new_email = reset_email or target["email"]
            c.execute("UPDATE identities SET email=?,password_hash=?,is_active=1,updated_at=? WHERE id=?",
                      (new_email, password_hash(reset_password), now(), target["id"]))
            c.execute("DELETE FROM sessions WHERE identity_id=?", (target["id"],))
            c.execute("INSERT INTO audit_events(id,event,actor_id,target_id,detail,created_at) VALUES(?,?,?,?,?,?)",
                      (str(uuid.uuid4()), "administrator_recovery", "deployment-recovery",
                       target["id"], "password reset; sessions revoked", now()))

    c.commit()
    c.close()


init_db()


class LoginRequest(BaseModel):
    email: str
    password: str


class IdentityCreate(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)
    email: Optional[str] = None
    password: Optional[str] = None
    identity_type: str = "human"
    access_class: str = "corporate"
    roles: list[str] = []


class IdentityUpdate(BaseModel):
    display_name: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    access_class: Optional[str] = None
    roles: Optional[list[str]] = None


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str = ""
    permissions: list[str] = []


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class ServiceCredentialRequest(BaseModel):
    label: str = Field(min_length=2, max_length=120)
    ttl_seconds: Optional[int] = Field(default=None, ge=300, le=31536000)


def _mfa_key() -> bytes:
    if not MFA_KEY_B64:
        raise HTTPException(503, "MFA encryption key is not configured")
    try:
        key = base64.b64decode(MFA_KEY_B64, validate=True)
    except Exception as exc:
        raise HTTPException(503, "MFA encryption key is invalid") from exc
    if len(key) != 32:
        raise HTTPException(503, "MFA encryption key must be 32 bytes")
    return key


def _mfa_secret_store(secret_b32: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_mfa_key()).encrypt(nonce, secret_b32.encode("ascii"), b"UNG-IAM-MFA-v1")
    return "enc:v1:" + base64.b64encode(nonce + ciphertext).decode("ascii")


def _mfa_secret_load(stored: str) -> str:
    if not stored.startswith("enc:v1:"):
        # Legacy plaintext factor. It is accepted temporarily and is re-encrypted
        # on the next successful confirmation/step-up.
        return stored
    try:
        raw = base64.b64decode(stored.split(":", 2)[2], validate=True)
        nonce, ciphertext = raw[:12], raw[12:]
        return AESGCM(_mfa_key()).decrypt(nonce, ciphertext, b"UNG-IAM-MFA-v1").decode("ascii")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Stored MFA factor cannot be decrypted") from exc


def _totp_code(secret_b32: str, at: Optional[float] = None) -> str:
    counter = int((at if at is not None else now()) // 30)
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def _totp_valid(secret_b32: str, code: str) -> bool:
    candidate = "".join(ch for ch in str(code) if ch.isdigit())
    if len(candidate) != 6:
        return False
    t = now()
    return any(hmac.compare_digest(_totp_code(secret_b32, t + step * 30), candidate) for step in (-1, 0, 1))


def permissions_for(c, identity_id: str) -> set[str]:
    rows = c.execute(
        """SELECT DISTINCT rp.permission_name
           FROM identity_roles ir
           JOIN role_permissions rp ON rp.role_id=ir.role_id
           WHERE ir.identity_id=?""",
        (identity_id,),
    ).fetchall()
    return {r["permission_name"] for r in rows}


def payload(c, row) -> dict:
    roles = [
        r["name"]
        for r in c.execute(
            "SELECT r.name FROM roles r JOIN identity_roles ir ON ir.role_id=r.id WHERE ir.identity_id=? ORDER BY r.name",
            (row["id"],),
        ).fetchall()
    ]
    return {
        "id": row["id"],
        "identity_type": row["identity_type"],
        "access_class": row["access_class"],
        "display_name": row["display_name"],
        "email": row["email"],
        "is_active": bool(row["is_active"]),
        "roles": roles,
        "permissions": sorted(permissions_for(c, row["id"])),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def resolve_principal(raw: str) -> Optional[dict]:
    """
    Resolve a bearer token to an identity.
    Checks both active sessions and valid service credentials.
    Updates last_used_at on successful service credential use.
    Returns identity payload with permissions, or None if token is invalid/expired.
    """
    token_hash = hash_token(raw)
    c = db()
    try:
        # Check for active session token first
        session = c.execute(
            """SELECT i.*, s.expires_at, s.created_at AS session_created_at, 'session' AS credential_kind
               FROM sessions s JOIN identities i ON i.id=s.identity_id
               WHERE s.token_hash=?""",
            (token_hash,),
        ).fetchone()
        if session and session["expires_at"] > now() and session["is_active"]:
            c.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now(), token_hash))
            mfa_row = c.execute("SELECT mfa_time FROM session_mfa WHERE token_hash=?", (token_hash,)).fetchone()
            c.commit()
            result = payload(c, session)
            result["auth_time"] = session["session_created_at"]
            result["credential_kind"] = "session"
            if mfa_row:
                result["mfa"] = True
                result["mfa_time"] = mfa_row["mfa_time"]
                result["amr"] = ["pwd", "otp", "mfa"]
                result["acr"] = "urn:ung:loa:scif-step-up"
            else:
                result["mfa"] = False
                result["amr"] = ["pwd"]
                result["acr"] = "urn:ung:loa:password"
            return result

        # Check for valid service credential
        service = c.execute(
            """SELECT i.*, sc.expires_at, 'service_credential' AS credential_kind
               FROM service_credentials sc JOIN identities i ON i.id=sc.identity_id
               WHERE sc.credential_hash=?""",
            (token_hash,),
        ).fetchone()
        if service and service["is_active"] and (service["expires_at"] is None or service["expires_at"] > now()):
            c.execute("UPDATE service_credentials SET last_used_at=? WHERE credential_hash=?", (now(), token_hash))
            c.commit()
            return payload(c, service)

        return None
    finally:
        c.close()


def resolve_scif_handle(raw: str) -> Optional[dict]:
    token_hash = hash_token(raw)
    c = db()
    try:
        row = c.execute(
            """SELECT h.identity_id,h.parent_token_hash,h.expires_at,
                      s.expires_at AS session_expires_at,s.created_at AS session_created_at,
                      i.*
               FROM scif_handles h
               JOIN sessions s ON s.token_hash=h.parent_token_hash
               JOIN identities i ON i.id=h.identity_id
               WHERE h.handle_hash=?""",
            (token_hash,),
        ).fetchone()
        if not row or row["expires_at"] <= now() or row["session_expires_at"] <= now() or not row["is_active"]:
            return None
        mfa_row = c.execute("SELECT mfa_time FROM session_mfa WHERE token_hash=?", (row["parent_token_hash"],)).fetchone()
        if not mfa_row:
            return None
        result = payload(c, row)
        result["auth_time"] = row["session_created_at"]
        result["credential_kind"] = "scif_handle"
        result["mfa"] = True
        result["mfa_time"] = mfa_row["mfa_time"]
        result["amr"] = ["pwd", "otp", "mfa"]
        result["acr"] = "urn:ung:loa:scif-step-up"
        return result
    finally:
        c.close()


def current_identity(authorization: str = Header(default="")) -> dict:
    """
    Dependency for endpoints requiring authentication.
    Accepts both session tokens and service credentials.
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    raw = authorization.split(" ", 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal:
        raise HTTPException(401, "Token invalid or expired")
    return principal


def require(permission: str):
    def dep(me: dict = Depends(current_identity)):
        if permission not in me["permissions"]:
            raise HTTPException(403, f"Missing permission: {permission}")
        return me
    return dep


@app.get("/")
def root():
    return {
        "system": "UNG IAM",
        "type": "Identity & Access Management Platform",
        "version": "1.1.0",
        "database": database_name(),
    }


@app.get("/health")
def health():
    c = None
    try:
        c = db()
        c.execute("SELECT 1").fetchone()
        return {
            "system": "UNG IAM",
            "status": "ok",
            "version": "1.1.0",
            "database": database_name(),
            "production_database": is_postgres(),
        }
    except Exception as exc:
        raise HTTPException(503, f"Database unavailable: {type(exc).__name__}")
    finally:
        if c:
            c.close()


class RecoveryIssueRequest(BaseModel):
    email: str


class RecoveryRedeemRequest(BaseModel):
    email: str
    code: str
    new_password: str


@app.post("/v1/auth/recovery/issue")
def issue_recovery(body: RecoveryIssueRequest):
    """Issue a short-lived single-use code only for the configured recovery identity."""
    email = body.email.strip().lower()
    c = db()
    row = c.execute("SELECT * FROM identities WHERE email=? AND identity_type='human' AND is_active=1", (email,)).fetchone()
    if not row:
        c.close()
        audit("recovery_issue_denied", detail=email)
        raise HTTPException(403, "Identity is not eligible for administrator recovery")
    admin = c.execute(
        """SELECT 1 FROM identity_roles ir
           JOIN roles r ON r.id=ir.role_id
           WHERE ir.identity_id=? AND r.name IN ('platform-admin','security-admin')
           LIMIT 1""",
        (row["id"],),
    ).fetchone()
    if not admin:
        c.close()
        audit("recovery_issue_denied", target_id=row["id"], detail="not_admin")
        raise HTTPException(403, "Identity is not eligible for administrator recovery")
    code = "-".join([f"{secrets.randbelow(10000):04d}" for _ in range(3)])
    c.execute("DELETE FROM recovery_codes WHERE identity_id=? AND used_at IS NULL", (row["id"],))
    c.execute("INSERT INTO recovery_codes(code_hash,identity_id,expires_at,used_at,created_at) VALUES(?,?,?,NULL,?)",
              (hash_token(code), row["id"], now() + 600, now()))
    c.commit()
    c.close()
    audit("recovery_code_issued", actor_id="self-recovery", target_id=row["id"], detail="expires_in=600")
    return {"email": email, "recovery_code": code, "expires_in": 600, "one_time_display": True}


@app.post("/v1/auth/recovery/redeem")
def redeem_recovery(body: RecoveryRedeemRequest):
    email = body.email.strip().lower()
    c = db()
    row = c.execute("SELECT * FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
    if not row:
        c.close()
        audit("recovery_failed", detail=email)
        raise HTTPException(401, "Invalid or expired recovery code")
    code_hash = hash_token(body.code.strip())
    rec = c.execute(
        "SELECT * FROM recovery_codes WHERE code_hash=? AND identity_id=? AND used_at IS NULL",
        (code_hash, row["id"]),
    ).fetchone()
    if not rec or rec["expires_at"] <= now():
        c.close()
        audit("recovery_failed", target_id=row["id"], detail="invalid_or_expired")
        raise HTTPException(401, "Invalid or expired recovery code")
    try:
        encoded = password_hash(body.new_password)
    except ValueError as exc:
        c.close()
        raise HTTPException(400, str(exc))
    c.execute("UPDATE identities SET password_hash=?,is_active=1,updated_at=? WHERE id=?",
              (encoded, now(), row["id"]))
    c.execute("UPDATE recovery_codes SET used_at=? WHERE code_hash=?", (now(), code_hash))
    c.execute("DELETE FROM sessions WHERE identity_id=?", (row["id"],))
    c.commit()
    c.close()
    audit("administrator_recovered", actor_id=row["id"], target_id=row["id"])
    return {"recovered": True, "email": email, "sessions_revoked": True}


@app.post("/v1/auth/login")
def login(body: LoginRequest):
    email = body.email.strip().lower()
    c = db()
    row = c.execute("SELECT * FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
    shared_email = os.getenv("UNG_IAM_SHARED_ADMIN_EMAIL", "").strip().lower()
    is_shared_admin = bool(shared_email and email == shared_email)
    if row and not row["is_active"]:
        c.close()
        audit("login_failed", detail=email)
        raise HTTPException(401, "Invalid credentials")
    # A locally recovered password takes precedence. Shared-admin verification
    # remains a fallback for the configured federated administrator.
    local_password_ok = bool(row and row["password_hash"] and password_valid(body.password, row["password_hash"]))
    if is_shared_admin and not local_password_ok:
        from shared_admin import verify_master
        try:
            verify_master(os.getenv("UNG_IAM_SHARED_AUTH_URL", ""), body.password)
            if not row:
                iid = str(uuid.uuid4())
                c.execute("INSERT OR IGNORE INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
                          (iid, "human", "corporate", "UNG Shared Administrator", email,
                           password_hash(secrets.token_urlsafe(48)), now(), now()))
                row = c.execute("SELECT * FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
            if not row or not row["is_active"]:
                raise HTTPException(401, "Invalid credentials")
            rid = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()
            if not rid:
                raise HTTPException(503, "Administrator role is not configured")
            c.execute("INSERT OR IGNORE INTO identity_roles(identity_id,role_id) VALUES(?,?)", (row["id"], rid["id"]))
        except Exception:
            c.rollback()
            c.close()
            audit("shared_admin_login_failed", detail=email)
            raise
    elif not local_password_ok:
        c.close()
        audit("login_failed", detail=email)
        raise HTTPException(401, "Invalid credentials")
    raw = "iam_" + secrets.token_urlsafe(48)
    th = hash_token(raw)
    c.execute("DELETE FROM sessions WHERE expires_at<=?", (now(),))
    c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (th, row["id"], now() + SESSION_TTL, now(), now()))
    who = payload(c, row)
    c.commit()
    c.close()
    audit("login_success", actor_id=row["id"])
    return {"access_token": raw, "token_type": "bearer", "expires_in": SESSION_TTL, "identity": who}


@app.post("/v1/auth/mfa/enroll")
def mfa_enroll(me: dict = Depends(current_identity)):
    if me.get("identity_type") != "human":
        raise HTTPException(400, "MFA enrollment is for human identities")
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    c = db()
    c.execute("DELETE FROM mfa_factors WHERE identity_id=?", (me["id"],))
    c.execute(
        "INSERT INTO mfa_factors(identity_id,secret,enabled,created_at,confirmed_at) VALUES(?,?,0,?,NULL)",
        (me["id"], _mfa_secret_store(secret), now()),
    )
    c.commit()
    c.close()
    issuer = "UNG-IAM"
    account = me.get("email") or me.get("display_name") or me["id"]
    audit("mfa_enrollment_started", actor_id=me["id"], target_id=me["id"])
    return {
        "secret": secret,
        "otpauth_uri": f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        "warning": "The secret is shown for enrollment. Protect it and confirm with a generated code.",
    }


@app.post("/v1/auth/mfa/confirm")
def mfa_confirm(body: MfaCodeRequest, me: dict = Depends(current_identity)):
    c = db()
    row = c.execute("SELECT * FROM mfa_factors WHERE identity_id=?", (me["id"],)).fetchone()
    if not row or not _totp_valid(_mfa_secret_load(row["secret"]), body.code):
        c.close()
        audit("mfa_enrollment_failed", actor_id=me["id"], target_id=me["id"])
        raise HTTPException(401, "Invalid MFA code")
    if not str(row["secret"]).startswith("enc:v1:"):
        c.execute("UPDATE mfa_factors SET secret=? WHERE identity_id=?", (_mfa_secret_store(_mfa_secret_load(row["secret"])), me["id"]))
    c.execute("UPDATE mfa_factors SET enabled=1,confirmed_at=? WHERE identity_id=?", (now(), me["id"]))
    c.commit()
    c.close()
    audit("mfa_enabled", actor_id=me["id"], target_id=me["id"])
    return {"mfa_enabled": True}


@app.post("/v1/auth/step-up")
def mfa_step_up(body: MfaCodeRequest, authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    raw = authorization.split(" ", 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal or principal.get("identity_type") != "human":
        raise HTTPException(401, "Active human session required")
    token_hash = hash_token(raw)
    c = db()
    session = c.execute("SELECT identity_id FROM sessions WHERE token_hash=? AND expires_at>?", (token_hash, now())).fetchone()
    factor = c.execute("SELECT * FROM mfa_factors WHERE identity_id=? AND enabled=1", (principal["id"],)).fetchone()
    if not session or not factor or not _totp_valid(_mfa_secret_load(factor["secret"]), body.code):
        c.close()
        audit("mfa_step_up_failed", actor_id=principal["id"], target_id=principal["id"])
        raise HTTPException(401, "MFA step-up failed")
    ts = now()
    if not str(factor["secret"]).startswith("enc:v1:"):
        c.execute("UPDATE mfa_factors SET secret=? WHERE identity_id=?", (_mfa_secret_store(_mfa_secret_load(factor["secret"])), principal["id"]))
    c.execute("DELETE FROM session_mfa WHERE token_hash=?", (token_hash,))
    c.execute("INSERT INTO session_mfa(token_hash,mfa_time) VALUES(?,?)", (token_hash, ts))
    c.commit()
    c.close()
    audit("mfa_step_up_success", actor_id=principal["id"], target_id=principal["id"])
    return {"mfa": True, "mfa_time": ts, "amr": ["pwd", "otp", "mfa"]}


@app.post("/v1/auth/introspect")
def introspect(authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        return {"active": False}
    raw = authorization.split(" ", 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal and raw.startswith("scif_"):
        principal = resolve_scif_handle(raw)
    if not principal:
        return {"active": False}
    return {"active": True, "principal": principal}


@app.post("/v1/auth/scif-handle")
def issue_scif_handle(authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    raw = authorization.split(" ", 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal or principal.get("identity_type") != "human":
        raise HTTPException(401, "Active human session required")
    parent_hash = hash_token(raw)
    c = db()
    try:
        mfa_row = c.execute("SELECT mfa_time FROM session_mfa WHERE token_hash=?", (parent_hash,)).fetchone()
        if not mfa_row:
            raise HTTPException(401, "Fresh MFA step-up required")
        age = now() - float(mfa_row["mfa_time"])
        if age < 0 or age > 300:
            raise HTTPException(401, "Fresh MFA step-up required")
        handle = "scif_" + secrets.token_urlsafe(48)
        handle_hash = hash_token(handle)
        c.execute("DELETE FROM scif_handles WHERE parent_token_hash=? OR expires_at<=?", (parent_hash, now()))
        c.execute(
            "INSERT INTO scif_handles(handle_hash,identity_id,parent_token_hash,expires_at,created_at) VALUES(?,?,?,?,?)",
            (handle_hash, principal["id"], parent_hash, now()+SCIF_HANDLE_TTL, now()),
        )
        c.commit()
    finally:
        c.close()
    audit("scif_handle_issued", actor_id=principal["id"], target_id=principal["id"])
    return {"access_token": handle, "token_type": "bearer", "expires_in": SCIF_HANDLE_TTL}


@app.post("/v1/auth/logout")
def logout(me: dict = Depends(current_identity)):
    c = db()
    th = hash_token(me["_original_token"]) if "_original_token" in me else None
    if th:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        c.commit()
    c.close()
    audit("logout", actor_id=me["id"])
    return {"logged_out": True}


@app.get("/v1/me")
def me(current: dict = Depends(current_identity)):
    current.pop("_original_token", None)
    return current


@app.get("/v1/identities")
def list_identities(admin: dict = Depends(require("iam:read"))):
    c = db()
    rows = c.execute("SELECT * FROM identities ORDER BY display_name").fetchall()
    result = [payload(c, r) for r in rows]
    c.close()
    return {"count": len(result), "results": result}


@app.post("/v1/identities")
def create_identity(body: IdentityCreate, admin: dict = Depends(require("iam:write"))):
    if body.identity_type not in {"human", "service"}:
        raise HTTPException(400, "identity_type must be human or service")
    if body.access_class not in {"corporate", "vendor", "contractor", "service"}:
        raise HTTPException(400, "Invalid access_class")
    if body.identity_type == "human" and (not body.email or not body.password):
        raise HTTPException(400, "Human identities require email and password")

    encoded = None
    if body.password:
        try:
            encoded = password_hash(body.password)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    iid = str(uuid.uuid4())
    email = body.email.strip().lower() if body.email else None
    c = db()
    try:
        c.execute(
            "INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)",
            (iid, body.identity_type, body.access_class, body.display_name.strip(), email, encoded, now(), now()),
        )
        for role_name in body.roles:
            r = c.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
            if not r:
                c.rollback()
                c.close()
                raise HTTPException(400, f"Unknown role: {role_name}")
            c.execute("INSERT OR IGNORE INTO identity_roles VALUES(?,?)", (iid, r["id"]))
        result = payload(c, c.execute("SELECT * FROM identities WHERE id=?", (iid,)).fetchone())
        c.commit()
        c.close()
    except sqlite3.IntegrityError:
        c.close()
        raise HTTPException(409, "Identity email already exists")
    audit("identity_created", admin["id"], iid, body.access_class)
    return result


@app.patch("/v1/identities/{identity_id}")
def update_identity(identity_id: str, body: IdentityUpdate, admin: dict = Depends(require("iam:write"))):
    c = db()
    row = c.execute("SELECT * FROM identities WHERE id=?", (identity_id,)).fetchone()
    if not row:
        c.close()
        raise HTTPException(404, "Identity not found")

    access_class = body.access_class if body.access_class is not None else row["access_class"]
    if access_class not in {"corporate", "vendor", "contractor", "service"}:
        c.close()
        raise HTTPException(400, "Invalid access_class")
    name = body.display_name.strip() if body.display_name is not None else row["display_name"]
    active = int(body.is_active) if body.is_active is not None else row["is_active"]
    encoded = row["password_hash"]
    if body.password is not None:
        try:
            encoded = password_hash(body.password)
        except ValueError as exc:
            c.close()
            raise HTTPException(400, str(exc))

    c.execute(
        "UPDATE identities SET display_name=?,access_class=?,password_hash=?,is_active=?,updated_at=? WHERE id=?",
        (name, access_class, encoded, active, now(), identity_id),
    )
    if body.roles is not None:
        c.execute("DELETE FROM identity_roles WHERE identity_id=?", (identity_id,))
        for role_name in body.roles:
            r = c.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
            if not r:
                c.rollback()
                c.close()
                raise HTTPException(400, f"Unknown role: {role_name}")
            c.execute("INSERT INTO identity_roles VALUES(?,?)", (identity_id, r["id"]))
    if body.is_active is False or body.password is not None:
        c.execute("DELETE FROM sessions WHERE identity_id=?", (identity_id,))

    result = payload(c, c.execute("SELECT * FROM identities WHERE id=?", (identity_id,)).fetchone())
    c.commit()
    c.close()
    audit("identity_updated", admin["id"], identity_id)
    return result


@app.post("/v1/identities/{identity_id}/revoke")
def revoke_identity(identity_id: str, admin: dict = Depends(require("iam:revoke"))):
    c = db()
    exists = c.execute("SELECT id FROM identities WHERE id=?", (identity_id,)).fetchone()
    if not exists:
        c.close()
        raise HTTPException(404, "Identity not found")
    sessions = c.execute("DELETE FROM sessions WHERE identity_id=?", (identity_id,)).rowcount
    credentials = c.execute("DELETE FROM service_credentials WHERE identity_id=?", (identity_id,)).rowcount
    c.commit()
    c.close()
    audit("identity_access_revoked", admin["id"], identity_id)
    return {"identity_id": identity_id, "sessions_revoked": sessions, "service_credentials_revoked": credentials}


@app.get("/v1/roles")
def list_roles(admin: dict = Depends(require("iam:read"))):
    c = db()
    roles = []
    for r in c.execute("SELECT * FROM roles ORDER BY name").fetchall():
        perms = [
            x["permission_name"]
            for x in c.execute(
                "SELECT permission_name FROM role_permissions WHERE role_id=? ORDER BY permission_name",
                (r["id"],),
            ).fetchall()
        ]
        roles.append({"id": r["id"], "name": r["name"], "description": r["description"], "permissions": perms})
    c.close()
    return {"count": len(roles), "results": roles}


@app.post("/v1/roles")
def create_role(body: RoleCreate, admin: dict = Depends(require("iam:roles"))):
    c = db()
    rid = str(uuid.uuid4())
    try:
        c.execute("INSERT INTO roles VALUES(?,?,?,?)", (rid, body.name.strip(), body.description.strip(), now()))
    except sqlite3.IntegrityError:
        c.close()
        raise HTTPException(409, "Role already exists")
    for perm in body.permissions:
        if not c.execute("SELECT name FROM permissions WHERE name=?", (perm,)).fetchone():
            c.rollback()
            c.close()
            raise HTTPException(400, f"Unknown permission: {perm}")
        c.execute("INSERT INTO role_permissions VALUES(?,?)", (rid, perm))
    c.commit()
    c.close()
    audit("role_created", admin["id"], rid, body.name)
    return {"id": rid, "name": body.name, "permissions": body.permissions}


@app.post("/v1/service-identities/{identity_id}/credentials")
def create_service_credential(
    identity_id: str,
    body: ServiceCredentialRequest,
    admin: dict = Depends(require("iam:write")),
):
    c = db()
    row = c.execute(
        "SELECT * FROM identities WHERE id=? AND identity_type='service' AND is_active=1",
        (identity_id,),
    ).fetchone()
    if not row:
        c.close()
        raise HTTPException(404, "Active service identity not found")
    raw = "svc_" + secrets.token_urlsafe(48)
    expiry = now() + body.ttl_seconds if body.ttl_seconds else None
    c.execute(
        "INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",
        (hash_token(raw), identity_id, body.label.strip(), expiry, now()),
    )
    c.commit()
    c.close()
    audit("service_credential_created", admin["id"], identity_id, body.label)
    return {
        "credential": raw,
        "label": body.label,
        "expires_at": expiry,
        "warning": "This credential is shown once. Store it securely.",
    }


@app.get("/v1/audit")
def audit_log(limit: int = 100, admin: dict = Depends(require("iam:audit"))):
    limit = max(1, min(500, limit))
    c = db()
    rows = c.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return {"count": len(rows), "results": [dict(r) for r in rows]}

