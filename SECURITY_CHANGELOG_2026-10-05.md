# 2026-10-05 IAM production security changes

- Seed `ung.core.ml.predict` and `ung.core.ml.train` permissions.
- Change Procfile to run `entrypoint:app` on Railway's `$PORT`.
- Add a production recovery-secret middleware requiring `X-UNG-Recovery-Secret` for `/v1/auth/recovery/issue`.
- Fail closed in production when `UNG_IAM_RECOVERY_SECRET` is absent.
- Add regression tests for the recovery gate.

Clean verification: 35 tests passed.
