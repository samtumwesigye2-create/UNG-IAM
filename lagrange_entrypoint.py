import entrypoint as iam
from ung_lagrange_adapter import create_lagrange_router

app = iam.app
app.include_router(create_lagrange_router('UNG-IAM', ['identity']))
