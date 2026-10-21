# Shared administrator sign-in

Set UNG_IAM_SHARED_ADMIN_EMAIL to the administrator email and UNG_IAM_SHARED_AUTH_URL to the HTTPS Grid API authority. Only that email uses the Grid master access code; other JANUS identities keep their existing password authentication.

JANUS checks the master code on every login through the authenticated, read-only /vector5250/profiles/bootstrap endpoint. It does not store or cache the shared password, follow redirects, or fall back to a local password on failure. A missing administrator identity is provisioned with a random local password hash and the platform-admin role. Disabled identities remain disabled.

Successful sign-in issues the existing JANUS session, with the configured session TTL (eight hours by default). VECTOR and VAULT continue to enforce their existing JANUS permissions. This administrator bridge does not migrate staff accounts or implement organization-wide staff SSO.

Run python -m unittest test_shared_admin test_authority to verify provisioning, disabled identities, local-password isolation, and fail-closed authority handling.
