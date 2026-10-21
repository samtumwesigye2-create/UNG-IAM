# IAM verification

Clean verification against the patched IAM package plus the recovery-entrypoint gate:

`pytest -q` -> `35 passed in 1.32s`

This branch also requires Railway production to start `entrypoint:app` and to define `UNG_IAM_RECOVERY_SECRET` before administrator recovery issuance is enabled.
