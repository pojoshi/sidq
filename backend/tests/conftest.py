import os

import psycopg
import pytest
from fastapi.testclient import TestClient

BASE = os.environ.get("TEST_DATABASE_URL", "postgresql://postgres@localhost:5432/sidq_test")


@pytest.fixture(scope="session", autouse=True)
def _schema():
    os.environ["DATABASE_URL"] = BASE
    from app import db
    db.init_schema()


@pytest.fixture(autouse=True)
def _clean():
    with psycopg.connect(BASE, autocommit=True) as c:
        c.execute("TRUNCATE cases, reports, campaigns RESTART IDENTITY CASCADE")
    os.environ.pop("OPERATOR_API_KEY", None)


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)
