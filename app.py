"""UNG IAM — standalone Identity & Access Management platform.

Independent from the legacy Uganda Grid application. Provides identity lifecycle,
role-based access control, opaque sessions, service identities and an audit trail.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("UNG_IAM_DATA_DIR", str(BASE / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("UNG_IAM_DB", str(DATA_DIR / "ung_iam.db")))
SESSION_TTL = max(300, int(os.environ.get("UNG_IAM_SESSION_TTL", "28800")))
BOOTSTRAP_EMAIL = os.environ.get("UNG_IAM_BOOTSTRAP_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.environ.get("UNG_IAM_BOOTSTRAP_PASSWORD", "")

app = FastAPI(title="UNG IAM", description="Uganda National Grid Identity & Access Management", version="1.0.0")


def now() -> float:
    return time.time()


def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


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
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=32)
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
        c.commit(); c.close()
    except Exception:
        pass


def init_db():
    c = db()
    c.executescript("""
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
    CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions(identity_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
    """)
    seed_permissions = {
        "iam:read":"Read identity and access configuration",
        "iam:write":"Create and update identities",
        "iam:roles":"Manage roles and permissions",
        "iam:audit":"Read IAM audit events",
        "iam:revoke":"Revoke sessions and credentials",
        "platform:corporate":"Access corporate-only systems",
        "platform:vendor":"Access approved vendor systems",
        "platform:contractor":"Access approved contractor systems",
        "platform:service":"System-to-system access",
    }
    for name, desc in seed_permissions.items():
        c.execute("INSERT OR IGNORE INTO permissions(name,description) VALUES(?,?)", (name, desc))
    roles = {
        "platform-admin": ("Full IAM administration", list(seed_permissions)),
        "security-admin": ("Security/access administration", ["iam:read","iam:roles","iam:audit","iam:revoke"]),
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
            c.execute("INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)", (
                iid,"human","corporate","UNG IAM Bootstrap Administrator",BOOTSTRAP_EMAIL,password_hash(BOOTSTRAP_PASSWORD),now(),now()
            ))
            rid = c.execute("SELECT id FROM roles WHERE name='platform-admin'").fetchone()["id"]
            c.execute("INSERT INTO identity_roles(identity_id,role_id) VALUES(?,?)", (iid, rid))
    c.commit(); c.close()


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


class ServiceCredentialRequest(BaseModel):
    label: str = Field(min_length=2, max_length=120)
    ttl_seconds: Optional[int] = Field(default=None, ge=300, le=31536000)


def permissions_for(c, identity_id: str) -> set[str]:
    rows = c.execute("""
      SELECT DISTINCT rp.permission_name FROM identity_roles ir
      JOIN role_permissions rp ON rp.role_id=ir.role_id WHERE ir.identity_id=?
    """, (identity_id,)).fetchall()
    return {r["permission_name"] for r in rows}


def payload(c, row) -> dict:
    roles = [r["name"] for r in c.execute(
        "SELECT r.name FROM roles r JOIN identity_roles ir ON ir.role_id=r.id WHERE ir.identity_id=? ORDER BY r.name",
        (row["id"],),
    ).fetchall()]
    return {
        "id":row["id"], "identity_type":row["identity_type"], "access_class":row["access_class"],
        "display_name":row["display_name"], "email":row["email"], "is_active":bool(row["is_active"]),
        "roles":roles, "permissions":sorted(permissions_for(c,row["id"])),
        "created_at":row["created_at"], "updated_at":row["updated_at"],
    }


def current_identity(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    raw = authorization.split(" ",1)[1].strip(); th = hash_token(raw); c = db()
    row = c.execute("""
      SELECT i.*,s.expires_at FROM sessions s JOIN identities i ON i.id=s.identity_id
      WHERE s.token_hash=?
    """, (th,)).fetchone()
    if not row or row["expires_at"] <= now() or not row["is_active"]:
        c.close(); raise HTTPException(401, "Session invalid or expired")
    c.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now(),th)); c.commit()
    result = payload(c,row); c.close(); result["_token_hash"] = th; return result


def require(permission: str):
    def dep(me: dict = Depends(current_identity)):
        if permission not in me["permissions"]:
            raise HTTPException(403, f"Missing permission: {permission}")
        return me
    return dep


@app.get("/")
def root():
    return {"system":"UNG IAM","type":"Identity & Access Management Platform","version":"1.0.0"}


@app.get("/health")
def health():
    return {"system":"UNG IAM","status":"ok","version":"1.0.0"}


@app.post("/v1/auth/login")
def login(body: LoginRequest):
    email = body.email.strip().lower(); c = db()
    row = c.execute("SELECT * FROM identities WHERE email=? AND identity_type='human'", (email,)).fetchone()
    if not row or not row["is_active"] or not row["password_hash"] or not password_valid(body.password,row["password_hash"]):
        c.close(); audit("login_failed",detail=email); raise HTTPException(401,"Invalid credentials")
    raw = "iam_" + secrets.token_urlsafe(48); th = hash_token(raw)
    c.execute("DELETE FROM sessions WHERE expires_at<=?", (now(),))
    c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (th,row["id"],now()+SESSION_TTL,now(),now()))
    who = payload(c,row); c.commit(); c.close(); audit("login_success",actor_id=row["id"])
    return {"access_token":raw,"token_type":"bearer","expires_in":SESSION_TTL,"identity":who}


@app.post("/v1/auth/logout")
def logout(me: dict = Depends(current_identity)):
    c=db(); c.execute("DELETE FROM sessions WHERE token_hash=?", (me["_token_hash"],)); c.commit(); c.close(); audit("logout",actor_id=me["id"])
    return {"logged_out":True}


@app.get("/v1/me")
def me(current: dict = Depends(current_identity)):
    current.pop("_token_hash",None); return current


@app.get("/v1/identities")
def list_identities(admin: dict = Depends(require("iam:read"))):
    c=db(); rows=c.execute("SELECT * FROM identities ORDER BY display_name").fetchall(); result=[payload(c,r) for r in rows]; c.close()
    return {"count":len(result),"results":result}


@app.post("/v1/identities")
def create_identity(body: IdentityCreate, admin: dict = Depends(require("iam:write"))):
    if body.identity_type not in {"human","service"}: raise HTTPException(400,"identity_type must be human or service")
    if body.access_class not in {"corporate","vendor","contractor","service"}: raise HTTPException(400,"Invalid access_class")
    if body.identity_type == "human" and (not body.email or not body.password): raise HTTPException(400,"Human identities require email and password")
    encoded=None
    if body.password:
        try: encoded=password_hash(body.password)
        except ValueError as e: raise HTTPException(400,str(e))
    iid=str(uuid.uuid4()); email=body.email.strip().lower() if body.email else None; c=db()
    try:
        c.execute("INSERT INTO identities VALUES(?,?,?,?,?,?,1,?,?)", (iid,body.identity_type,body.access_class,body.display_name.strip(),email,encoded,now(),now()))
        for role_name in body.roles:
            r=c.execute("SELECT id FROM roles WHERE name=?",(role_name,)).fetchone()
            if not r: raise HTTPException(400,f"Unknown role: {role_name}")
            c.execute("INSERT OR IGNORE INTO identity_roles VALUES(?,?)",(iid,r["id"]))
        result=payload(c,c.execute("SELECT * FROM identities WHERE id=?",(iid,)).fetchone()); c.commit(); c.close()
    except sqlite3.IntegrityError:
        c.close(); raise HTTPException(409,"Identity email already exists")
    audit("identity_created",admin["id"],iid,body.access_class); return result


@app.patch("/v1/identities/{identity_id}")
def update_identity(identity_id: str, body: IdentityUpdate, admin: dict = Depends(require("iam:write"))):
    c=db(); row=c.execute("SELECT * FROM identities WHERE id=?",(identity_id,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Identity not found")
    access_class=body.access_class if body.access_class is not None else row["access_class"]
    if access_class not in {"corporate","vendor","contractor","service"}: c.close(); raise HTTPException(400,"Invalid access_class")
    name=body.display_name.strip() if body.display_name is not None else row["display_name"]
    active=int(body.is_active) if body.is_active is not None else row["is_active"]; encoded=row["password_hash"]
    if body.password is not None:
        try: encoded=password_hash(body.password)
        except ValueError as e: c.close(); raise HTTPException(400,str(e))
    c.execute("UPDATE identities SET display_name=?,access_class=?,password_hash=?,is_active=?,updated_at=? WHERE id=?",(name,access_class,encoded,active,now(),identity_id))
    if body.roles is not None:
        c.execute("DELETE FROM identity_roles WHERE identity_id=?",(identity_id,))
        for role_name in body.roles:
            r=c.execute("SELECT id FROM roles WHERE name=?",(role_name,)).fetchone()
            if not r: c.close(); raise HTTPException(400,f"Unknown role: {role_name}")
            c.execute("INSERT INTO identity_roles VALUES(?,?)",(identity_id,r["id"]))
    if body.is_active is False or body.password is not None:
        c.execute("DELETE FROM sessions WHERE identity_id=?",(identity_id,))
    result=payload(c,c.execute("SELECT * FROM identities WHERE id=?",(identity_id,)).fetchone()); c.commit(); c.close(); audit("identity_updated",admin["id"],identity_id)
    return result


@app.post("/v1/identities/{identity_id}/revoke")
def revoke_identity(identity_id: str, admin: dict = Depends(require("iam:revoke"))):
    c=db(); exists=c.execute("SELECT id FROM identities WHERE id=?",(identity_id,)).fetchone()
    if not exists: c.close(); raise HTTPException(404,"Identity not found")
    sessions=c.execute("DELETE FROM sessions WHERE identity_id=?",(identity_id,)).rowcount
    credentials=c.execute("DELETE FROM service_credentials WHERE identity_id=?",(identity_id,)).rowcount
    c.commit(); c.close(); audit("identity_access_revoked",admin["id"],identity_id)
    return {"identity_id":identity_id,"sessions_revoked":sessions,"service_credentials_revoked":credentials}


@app.get("/v1/roles")
def list_roles(admin: dict = Depends(require("iam:read"))):
    c=db(); roles=[]
    for r in c.execute("SELECT * FROM roles ORDER BY name").fetchall():
        perms=[x["permission_name"] for x in c.execute("SELECT permission_name FROM role_permissions WHERE role_id=? ORDER BY permission_name",(r["id"],)).fetchall()]
        roles.append({"id":r["id"],"name":r["name"],"description":r["description"],"permissions":perms})
    c.close(); return {"count":len(roles),"results":roles}


@app.post("/v1/roles")
def create_role(body: RoleCreate, admin: dict = Depends(require("iam:roles"))):
    c=db(); rid=str(uuid.uuid4())
    try: c.execute("INSERT INTO roles VALUES(?,?,?,?)",(rid,body.name.strip(),body.description.strip(),now()))
    except sqlite3.IntegrityError: c.close(); raise HTTPException(409,"Role already exists")
    for perm in body.permissions:
        if not c.execute("SELECT name FROM permissions WHERE name=?",(perm,)).fetchone(): c.close(); raise HTTPException(400,f"Unknown permission: {perm}")
        c.execute("INSERT INTO role_permissions VALUES(?,?)",(rid,perm))
    c.commit(); c.close(); audit("role_created",admin["id"],rid,body.name); return {"id":rid,"name":body.name,"permissions":body.permissions}


@app.post("/v1/service-identities/{identity_id}/credentials")
def create_service_credential(identity_id: str, body: ServiceCredentialRequest, admin: dict = Depends(require("iam:write"))):
    c=db(); row=c.execute("SELECT * FROM identities WHERE id=? AND identity_type='service' AND is_active=1",(identity_id,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Active service identity not found")
    raw="svc_"+secrets.token_urlsafe(48); expiry=now()+body.ttl_seconds if body.ttl_seconds else None
    c.execute("INSERT INTO service_credentials VALUES(?,?,?,?,?,NULL)",(hash_token(raw),identity_id,body.label.strip(),expiry,now())); c.commit(); c.close()
    audit("service_credential_created",admin["id"],identity_id,body.label)
    return {"credential":raw,"label":body.label,"expires_at":expiry,"warning":"This credential is shown once. Store it securely."}


@app.get("/v1/audit")
def audit_log(limit: int = 100, admin: dict = Depends(require("iam:audit"))):
    limit=max(1,min(500,limit)); c=db(); rows=c.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return {"count":len(rows),"results":[dict(r) for r in rows]}
