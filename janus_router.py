from fastapi import APIRouter, Header, HTTPException
from app import db, hash_token, now, payload, permissions_for

router = APIRouter(prefix='/v1/auth', tags=['JANUS'])


def resolve_principal(raw: str):
    token_hash = hash_token(raw)
    c = db()
    try:
        session = c.execute(
            """SELECT i.*, s.expires_at, 'human' AS credential_kind
               FROM sessions s JOIN identities i ON i.id=s.identity_id
               WHERE s.token_hash=?""",
            (token_hash,),
        ).fetchone()
        if session and session['expires_at'] > now() and session['is_active']:
            c.execute('UPDATE sessions SET last_seen_at=? WHERE token_hash=?', (now(), token_hash))
            c.commit()
            principal = payload(c, session)
            principal['credential_kind'] = 'session'
            principal['expires_at'] = session['expires_at']
            return principal

        service = c.execute(
            """SELECT i.*, sc.expires_at
               FROM service_credentials sc JOIN identities i ON i.id=sc.identity_id
               WHERE sc.credential_hash=?""",
            (token_hash,),
        ).fetchone()
        if service and service['is_active'] and (service['expires_at'] is None or service['expires_at'] > now()):
            c.execute('UPDATE service_credentials SET last_used_at=? WHERE credential_hash=?', (now(), token_hash))
            c.commit()
            principal = payload(c, service)
            principal['credential_kind'] = 'service_credential'
            principal['expires_at'] = service['expires_at']
            return principal
        return None
    finally:
        c.close()


@router.post('/introspect')
def introspect(authorization: str = Header(default='')):
    if not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Bearer token required')
    raw = authorization.split(' ', 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal:
        raise HTTPException(401, 'Token invalid or expired')
    return {'active': True, 'principal': principal}


@router.get('/authorize')
def authorize(permission: str, authorization: str = Header(default='')):
    if not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Bearer token required')
    raw = authorization.split(' ', 1)[1].strip()
    principal = resolve_principal(raw)
    if not principal:
        raise HTTPException(401, 'Token invalid or expired')
    allowed = permission in principal.get('permissions', [])
    return {
        'active': True,
        'allowed': allowed,
        'permission': permission,
        'principal_id': principal['id'],
        'identity_type': principal['identity_type'],
        'credential_kind': principal['credential_kind'],
    }
