import os

from fastapi.testclient import TestClient
import entrypoint


def test_production_recovery_request_is_blocked_without_secret(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.delenv("UNG_IAM_RECOVERY_SECRET", raising=False)
    client = TestClient(entrypoint.app)
    response = client.post("/v1/auth/recovery/issue", json={"email": "admin@example.invalid"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator recovery requires the recovery secret"
