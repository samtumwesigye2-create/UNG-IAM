from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from main import app as console_app
from sso_router import router as sso_router
from janus_router import router as janus_router
from ecosystem_permissions import seed_ecosystem_permissions

COOKIE_NAME = "ung_iam_session"
COOKIE_MAX_AGE = 28800

seed_ecosystem_permissions()


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
app.include_router(sso_router)
app.include_router(janus_router)
app.mount("/", console_app)
