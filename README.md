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


## SCIF step-up MFA
UNG IAM now provides TOTP-based multi-factor enrollment and explicit step-up authentication for high-assurance applications such as UNG-VAULT Digital SCIF.

- `POST /v1/auth/mfa/enroll` starts TOTP enrollment and returns an `otpauth://` URI.
- `POST /v1/auth/mfa/confirm` confirms enrollment with a 6-digit code.
- `POST /v1/auth/step-up` verifies a fresh TOTP code for the current bearer session.
- `POST /v1/auth/introspect` returns the current principal plus MFA evidence.
- Step-up evidence includes `mfa=true`, `mfa_time`, `amr`, `acr`, and session `auth_time`.
- MFA state is session-specific. A new login does not inherit a prior session's step-up.


## Encrypted MFA factor storage
TOTP seed material used for SCIF step-up is encrypted at rest before being written to the IAM database.

- `UNG_IAM_MFA_KEY_B64` must contain a base64-encoded 32-byte AES key.
- New MFA factors are stored with AES-256-GCM using a fresh nonce and authenticated context.
- Legacy plaintext factors remain temporarily readable only for migration and are automatically re-encrypted after the next successful MFA confirmation or step-up.
- MFA factor encryption is separate from password hashing and bearer-session hashing.
