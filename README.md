# UNG IAM — Identity & Access Management Platform

UNG IAM is the independent identity authority for the Uganda National Grid ecosystem.

## Responsibilities

- Human identities for corporate users, vendors and contractors
- Service identities for system-to-system access
- Role-based access control (RBAC)
- Permission assignment and access classification
- Secure password hashing using scrypt
- Opaque bearer sessions stored only as hashes
- Session and service-credential revocation
- Identity disablement
- IAM security audit trail
- Bootstrap administrator for first deployment

## Isolation rule

UNG IAM is a standalone top-level system. It must use its own repository, deployment and database. Other UNG systems consume IAM through authenticated APIs; they must not import IAM application code or share its database.

## Environment

- `UNG_IAM_DB` — optional database file path
- `UNG_IAM_DATA_DIR` — persistent data directory when `UNG_IAM_DB` is not specified
- `UNG_IAM_SESSION_TTL` — human session lifetime in seconds; default 28800
- `UNG_IAM_BOOTSTRAP_EMAIL` — first administrator email
- `UNG_IAM_BOOTSTRAP_PASSWORD` — first administrator password; minimum 12 characters

For production, set bootstrap credentials through the deployment platform's secret/environment store, create a permanent administrator, then rotate/remove bootstrap credentials.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

Health endpoint: `GET /health`

## Core API

- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `GET /v1/me`
- `GET /v1/identities`
- `POST /v1/identities`
- `PATCH /v1/identities/{identity_id}`
- `POST /v1/identities/{identity_id}/revoke`
- `GET /v1/roles`
- `POST /v1/roles`
- `POST /v1/service-identities/{identity_id}/credentials`
- `GET /v1/audit`

## Integration architecture

UNG IAM will issue and manage identities while UNG Sentinel remains the security monitoring and protection authority. Applications such as UGAMAP, UGASHIP, WMS400Vector, UGAFORCE-HR, UNG-UAS and future platforms should validate identity/access through IAM integration instead of maintaining independent long-term identity stores.
