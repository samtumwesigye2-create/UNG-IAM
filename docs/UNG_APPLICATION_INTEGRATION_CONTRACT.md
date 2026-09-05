# UNG Application Integration Contract

Status: baseline contract for all UNG applications integrating with UNG-IAM.

## 1. Identity authority

UNG-IAM is the sole long-term identity authority for the UNG application suite. Applications must not create independent permanent password stores or duplicate IAM role databases.

## 2. Supported principals

- Human identities authenticate with `POST /v1/auth/login` and receive an opaque bearer token.
- Service identities receive one-time service credentials from `POST /v1/service-identities/{identity_id}/credentials`.
- Applications treat the bearer credential as opaque. They must not parse or infer identity data from the token value.

## 3. Required application identity

Every UNG application must declare a stable application ID. Initial IDs:

- `ung-mdm`
- `ung-eam`
- `ung-fin`
- `ung-data`
- `ung-procure`
- `ung-docs`
- `ung-comms`
- `ung-bcm`
- `ung-sentinel`
- `ung-noc`
- `wms400vector`
- `ung-infra-25`
- `ung-uas`

Application IDs are lowercase, immutable, and used in audit events, access policies, service-to-service calls, and configuration.

## 4. Authentication flow

1. User signs in through UNG-IAM.
2. The application receives the opaque bearer token from the approved client flow.
3. The application calls UNG-IAM `GET /v1/me` with `Authorization: Bearer <token>`.
4. UNG-IAM returns the authoritative identity, roles, permissions, access class, and active state.
5. The application denies access if IAM returns 401/403, the identity is inactive, or required application permissions are absent.
6. Logout calls `POST /v1/auth/logout` and the local application session is destroyed.

## 5. Authorization model

Applications authorize on permissions, not display names or email addresses.

Each protected action declares one or more required permissions. Application code performs a deny-by-default subset check against the `permissions` returned by IAM.

Recommended permission namespaces:

- `mdm:*`
- `eam:*`
- `fin:*`
- `data:*`
- `procure:*`
- `docs:*`
- `comms:*`
- `bcm:*`
- `sentinel:*`
- `noc:*`
- `wms:*`
- `infra:*`
- `uas:*`

Examples: `mdm:read`, `mdm:write`, `fin:approve`, `procure:award`, `sentinel:investigate`.

The existing platform permissions (`platform:corporate`, `platform:vendor`, `platform:contractor`, `platform:service`) are coarse access-class gates and do not replace application-specific permissions.

## 6. Required identity payload

Applications must support at least these IAM fields:

```json
{
  "id": "stable-identity-id",
  "identity_type": "human",
  "access_class": "corporate",
  "display_name": "Example User",
  "email": "user@example.org",
  "is_active": true,
  "roles": ["corporate-user"],
  "permissions": ["platform:corporate"],
  "created_at": 0,
  "updated_at": 0
}
```

Applications must key user ownership and audit references by `id`, never by mutable email or display name.

## 7. Session rules

- Bearer tokens are secrets and must never be written to logs.
- Browser applications keep tokens only in approved secure session storage/cookies appropriate to the final frontend architecture.
- Backend logs may record identity ID, application ID, action, result, correlation ID, and timestamp, but never the credential.
- A 401 response from IAM immediately invalidates the local application session.
- A 403 response is an authorization denial, not a reason to retry credentials.

## 8. Revocation

IAM remains authoritative for revocation. Applications must not continue honoring a locally cached identity after IAM has rejected the credential.

For sensitive operations, authorization must be checked against IAM at request time. For low-risk reads, a short-lived local cache may be used only after a production cache TTL is explicitly approved.

## 9. Audit contract

Every application audit event should include:

- `application_id`
- `event`
- `actor_identity_id`
- `target_type`
- `target_id`
- `result`
- `correlation_id`
- `created_at`

Security-relevant events should be forwarded to UNG-SENTINEL when its ingestion contract is activated.

## 10. Service-to-service contract

Service identities use IAM-issued service credentials. Each service credential belongs to one service identity and must be independently revocable. Applications must identify the calling service by the IAM identity ID and apply service-specific permissions.

No UNG service may authenticate to another service using a shared human account.

## 11. Failure behavior

Fail closed. If IAM is unavailable and no explicitly approved resilience policy exists for the endpoint, protected writes and privileged actions are denied rather than bypassing authentication.

## 12. Integration acceptance test

An application is considered IAM-integrated only when all of these pass:

1. Valid human login succeeds.
2. Invalid credentials fail.
3. `GET /v1/me` resolves the logged-in identity.
4. Required permission allows an authorized request.
5. Missing permission returns an application 403.
6. Logout invalidates the IAM session.
7. Revoked identity/token cannot access the application.
8. Disabled identity cannot access the application.
9. Audit records contain the IAM identity ID and application ID.
10. No password database exists in the application itself.

This contract is versioned with UNG-IAM and applies to every new UNG application unless a later approved contract supersedes it.
