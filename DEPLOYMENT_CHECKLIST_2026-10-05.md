# Deployment checklist

1. Merge this branch to `main`.
2. In Railway production, set the start command to `uvicorn entrypoint:app --host 0.0.0.0 --port $PORT`.
3. Set `UNG_IAM_RECOVERY_SECRET` to a strong random secret.
4. Deploy.
5. Verify `/health` returns 200.
6. Verify POST `/v1/auth/recovery/issue` without `X-UNG-Recovery-Secret` returns 403.
7. Verify the same request with the configured secret reaches IAM's eligibility checks.
8. Confirm CORE ML permissions are present after IAM startup.
