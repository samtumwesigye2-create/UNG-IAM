"""Database compatibility layer for UNG IAM.

Production uses the dedicated PostgreSQL service through UNG_IAM_DATABASE_URL.
SQLite remains available only as a local-development fallback.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

DATABASE_URL = os.environ.get("UNG_IAM_DATABASE_URL", "").strip()
BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("UNG_IAM_DATA_DIR", str(BASE / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_PATH = Path(os.environ.get("UNG_IAM_DB", str(DATA_DIR / "ung_iam.db")))


def _postgres() -> bool:
    return DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")


class Row(dict):
    pass


class Cursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        row = self._cursor.fetchone()
        return Row(row) if row is not None and not isinstance(row, sqlite3.Row) else row

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [Row(r) if not isinstance(r, sqlite3.Row) else r for r in rows]


class Connection:
    def __init__(self):
        self.pg = _postgres()
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            self._psycopg = psycopg
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
        else:
            self._psycopg = None
            self.conn = sqlite3.connect(SQLITE_PATH, timeout=30)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA journal_mode=WAL")

    def _sql(self, sql: str) -> str:
        if not self.pg:
            return sql
        return sql.replace("?", "%s")

    def execute(self, sql: str, params=()):
        if self.pg and "INSERT OR IGNORE" in sql.upper():
            sql = re.sub(r"INSERT\s+OR\s+IGNORE", "INSERT", sql, flags=re.I)
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        try:
            cur = self.conn.execute(self._sql(sql), params)
            return Cursor(cur)
        except Exception as exc:
            if self.pg and self._psycopg and isinstance(exc, self._psycopg.IntegrityError):
                self.conn.rollback()
                raise sqlite3.IntegrityError(str(exc)) from exc
            raise

    def executescript(self, script: str):
        if not self.pg:
            return self.conn.executescript(script)
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.conn.execute(statement)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def connect() -> Connection:
    return Connection()


def is_postgres() -> bool:
    return _postgres()


def database_name() -> str:
    return "postgresql" if _postgres() else "sqlite"
