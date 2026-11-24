import sqlite3

import pytest

from app import create_app
from app.auth import issue_access_token


TEST_SIGNING_KEY = bytes(range(32))


@pytest.fixture
def app_client(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "TOKEN_SIGNING_KEY": TEST_SIGNING_KEY,
        }
    )
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "INSERT INTO accounts (id, owner_id, balance_cents) VALUES (?, ?, ?)",
            (
                ("alice-checking", "alice", 10000),
                ("bob-checking", "bob", 5000),
            ),
        )
        connection.executemany(
            "INSERT INTO orders (id, owner_id, status) VALUES (?, ?, ?)",
            (
                ("alice-pending", "alice", "pending"),
                ("bob-pending", "bob", "pending"),
                ("alice-fulfilled", "alice", "fulfilled"),
            ),
        )

    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    def make_headers(user_id):
        token = issue_access_token(user_id, TEST_SIGNING_KEY)
        return {"Authorization": f"Bearer {token}"}

    return make_headers
