from fastapi import FastAPI

from main import app as console_app
from sso_router import router as sso_router

app = FastAPI(title="UNG IAM", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(sso_router)
app.mount("/", console_app)
