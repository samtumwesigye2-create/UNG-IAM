FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py db.py main.py sso_router.py janus_router.py ecosystem_permissions.py entrypoint.py ./
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "uvicorn entrypoint:app --host 0.0.0.0 --port ${PORT:-8000}"]
