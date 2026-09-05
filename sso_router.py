from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from db import connect

router = APIRouter()
CODE_TTL = 90
SESSION_TTL = max(300, int(os.environ.get("UNG_IAM_SESSION_TTL", "28800")))
COOKIE_NAME = "ung_iam_session"
DEFAULT_CLIENTS = {
    "UNG-MDM": ["https://ung-mdm-production.up.railway.app/sso/callback"],
}


def now() -> float:
    return time.time()


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def clients() -> dict[str, list[str]]:
    raw = os.environ.get("UNG_IAM_SSO_CLIENTS", "").strip()
    if not raw:
        return DEFAULT_CLIENTS
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError
        return {str(k): [str(x) for x in v] for k, v in parsed.items() if isinstance(v, list)}
    except Exception:
        raise RuntimeError("Invalid UNG_IAM_SSO_CLIENTS JSON")


def ensure_schema() -> None:
    c = connect()
    try:
        c.execute(
            """CREATE TABLE IF NOT EXISTS sso_codes(
                code_hash TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL
            )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_sso_codes_expiry ON sso_codes(expires_at)")
        c.commit()
    finally:
        c.close()


ensure_schema()


def identity_from_session(authorization: str, request: Request) -> dict:
    raw = ""
    if authorization.lower().startswith("bearer "):
        raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        raw = request.cookies.get(COOKIE_NAME, "").strip()
    if not raw:
        raise HTTPException(401, "Active UNG-IAM browser session required")

    c = connect()
    try:
        row = c.execute(
            """SELECT i.*, s.expires_at
               FROM sessions s JOIN identities i ON i.id=s.identity_id
               WHERE s.token_hash=?""",
            (hash_token(raw),),
        ).fetchone()
        if not row or row["expires_at"] <= now() or not row["is_active"]:
            raise HTTPException(401, "Session invalid or expired")
        roles = [r["name"] for r in c.execute(
            "SELECT r.name FROM roles r JOIN identity_roles ir ON ir.role_id=r.id WHERE ir.identity_id=? ORDER BY r.name",
            (row["id"],),
        ).fetchall()]
        perms = [r["permission_name"] for r in c.execute(
            """SELECT DISTINCT rp.permission_name FROM identity_roles ir
               JOIN role_permissions rp ON rp.role_id=ir.role_id
               WHERE ir.identity_id=? ORDER BY rp.permission_name""",
            (row["id"],),
        ).fetchall()]
        return {
            "id": row["id"], "display_name": row["display_name"], "email": row["email"],
            "identity_type": row["identity_type"], "access_class": row["access_class"],
            "is_active": bool(row["is_active"]), "roles": roles, "permissions": perms,
        }
    finally:
        c.close()


class CodeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    code_challenge: str
    state: str


class TokenRequest(BaseModel):
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str


def validate_client(client_id: str, redirect_uri: str) -> None:
    allowed = clients().get(client_id, [])
    if redirect_uri not in allowed:
        raise HTTPException(400, "Invalid client or redirect URI")


@router.get("/sso/launch", response_class=HTMLResponse)
def launch(client_id: str, redirect_uri: str, code_challenge: str, state: str):
    validate_client(client_id, redirect_uri)
    safe_query = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "state": state,
    })
    html = f'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>UNG SSO</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f6f8;margin:0;padding:24px;color:#111827}}.card{{max-width:520px;margin:10vh auto;background:white;padding:24px;border-radius:20px;border:1px solid #e5e7eb}}button{{width:100%;padding:14px;border:0;border-radius:12px;background:#101828;color:white;font-weight:750}}p{{color:#667085}}.err{{color:#b42318}}</style></head><body><div class="card"><h2>Continue with UNG Identity</h2><p>This will use your current UNG-IAM browser session to sign you into {client_id}.</p><button id="go">Continue to {client_id}</button><p id="msg" class="err"></p></div>
<script>
const q=new URLSearchParams('{safe_query}');
async function go(){{
 const r=await fetch('/v1/sso/code',{{method:'POST',credentials:'same-origin',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(Object.fromEntries(q.entries()))}});
 const d=await r.json();
 if(!r.ok){{document.getElementById('msg').textContent=d.detail||'SSO authorization failed. Return to UNG-IAM and sign in first.';return;}}
 location.href=d.redirect_to;
}}
document.getElementById('go').onclick=go;go();
</script></body></html>'''
    return HTMLResponse(html, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@router.post("/v1/sso/code")
def issue_code(body: CodeRequest, request: Request, authorization: str = Header(default="")):
    validate_client(body.client_id, body.redirect_uri)
    if len(body.code_challenge) < 40 or len(body.state) < 16:
        raise HTTPException(400, "Invalid PKCE/state parameters")
    identity = identity_from_session(authorization, request)
    raw_code = "sso_" + secrets.token_urlsafe(36)
    c = connect()
    try:
        c.execute("DELETE FROM sso_codes WHERE expires_at<=? OR used_at IS NOT NULL", (now(),))
        c.execute(
            "INSERT INTO sso_codes(code_hash,identity_id,client_id,redirect_uri,code_challenge,expires_at,used_at) VALUES(?,?,?,?,?,?,NULL)",
            (hash_token(raw_code), identity["id"], body.client_id, body.redirect_uri, body.code_challenge, now() + CODE_TTL),
        )
        c.commit()
    finally:
        c.close()
    return {"redirect_to": body.redirect_uri + "?" + urlencode({"code": raw_code, "state": body.state})}


@router.post("/v1/sso/token")
def exchange_code(body: TokenRequest):
    validate_client(body.client_id, body.redirect_uri)
    c = connect()
    try:
        row = c.execute("SELECT * FROM sso_codes WHERE code_hash=?", (hash_token(body.code),)).fetchone()
        if not row or row["used_at"] is not None or row["expires_at"] <= now():
            raise HTTPException(400, "Authorization code invalid or expired")
        if row["client_id"] != body.client_id or row["redirect_uri"] != body.redirect_uri:
            raise HTTPException(400, "Authorization code binding mismatch")
        if b64url_sha256(body.code_verifier) != row["code_challenge"]:
            raise HTTPException(400, "PKCE verification failed")
        identity = c.execute("SELECT * FROM identities WHERE id=? AND is_active=1", (row["identity_id"],)).fetchone()
        if not identity:
            raise HTTPException(403, "Identity unavailable")
        raw_session = "iam_" + secrets.token_urlsafe(48)
        ts = now()
        c.execute("UPDATE sso_codes SET used_at=? WHERE code_hash=?", (ts, hash_token(body.code)))
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hash_token(raw_session), identity["id"], ts + SESSION_TTL, ts, ts))
        c.commit()
        return {"access_token": raw_session, "token_type": "bearer", "expires_in": SESSION_TTL}
    finally:
        c.close()
