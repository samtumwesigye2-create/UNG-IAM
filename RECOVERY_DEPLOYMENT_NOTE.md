# IAM recovery deployment requirement

Production must run `entrypoint:app`, not `main:app`, because the recovery-secret middleware is attached in `entrypoint.py`.

Required Railway variable: `UNG_IAM_RECOVERY_SECRET`.

The administrator recovery issue endpoint requires `X-UNG-Recovery-Secret` in production. Without the variable configured, the middleware denies recovery issuance in production.
