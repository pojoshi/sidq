import os
import pathlib
from contextlib import contextmanager

import psycopg
from pgvector.psycopg import register_vector
from psycopg.rows import dict_row


def dsn():
    return os.environ.get("DATABASE_URL", "postgresql://postgres@localhost:5432/sidq")


@contextmanager
def conn():
    with psycopg.connect(dsn(), row_factory=dict_row) as c:
        register_vector(c)
        yield c


def init_schema():
    sql = (pathlib.Path(__file__).resolve().parent.parent / "schema.sql").read_text()
    with psycopg.connect(dsn(), autocommit=True) as c:
        c.execute(sql)
