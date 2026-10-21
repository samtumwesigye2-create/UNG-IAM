import hmac
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from main import app as console_app
from sso_router import router as sso_router
from janus_router import router as janus_router
from ecosystem_permissions import seed_ecosystem_permissions
from scripts.provision_remote_sensor_hub import main as provision_remote_sensor_hub
from scripts.backbone_acceptance_once import main as run_backbone_acceptance_once

COOKIE_NAME = "ung_iam_session"
COOKIE_MAX_AGE = 28800

seed_ecosystem_permissions()
provision_remote_sensor_hub()
run_backbone_acceptance_once()


def _is_production() -> bool:
    values = [
        os.getenv("RAILWAY_ENVIRONMENT", ""),
        os.getenv("RAILWAY_ENVIRONMENT_NAME", ""),
        os.getenv("ENV", ""),
        os.getenv("ENVIRONMENT", ""),
    ]
    return any(str(v).strip().lower() in {"production", "prod"} for v in values)


def _recovery_secret_allowed(provided: str, expected: str, production: bool) -> bool:
    if expected:
        return bool(provided) and hmac.compare_digest(provided.encode(), expected.encode())
    return not production


class RecoverySecretMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/v1/auth/recovery/issue" and request.method.upper() == "POST":
            expected = os.getenv("UNG_IAM_RECOVERY_SECRET", "")
            provided = request.headers.get("x-ung-recovery-secret", "")
            if not _recovery_secret_allowed(provided, expected, _is_production()):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Administrator recovery requires the recovery secret"},
                )
        return await call_next(request)


class BrowserSessionCookieMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        authorization = request.headers.get("authorization", "")
        if response.status_code < 400 and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
            if token:
                response.set_cookie(
                    COOKIE_NAME,
                    token,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    path="/",
                )
        if request.url.path == "/v1/auth/logout" and response.status_code < 400:
            response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="lax")
        return response


app = FastAPI(title="UNG IAM", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(BrowserSessionCookieMiddleware)
app.add_middleware(RecoverySecretMiddleware)
app.include_router(sso_router)
app.include_router(janus_router)
app.mount("/", console_app)
