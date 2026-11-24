import sqlite3

def _balances(database):
    with sqlite3.connect(database) as connection:
        return dict(connection.execute("SELECT id, balance_cents FROM accounts"))


def test_transfer_requires_ownership_of_source_account(
    app_client,
    auth_headers,
):
    database = app_client.application.config["DATABASE"]
    before = _balances(database)

    response = app_client.post(
        "/transfers",
        headers=auth_headers("alice"),
        json={
            "sender_account_id": "bob-checking",
            "recipient_account_id": "alice-checking",
            "amount_cents": 1000,
        },
    )

    assert response.status_code == 404
    assert _balances(database) == before

    own_transfer = app_client.post(
        "/transfers",
        headers=auth_headers("alice"),
        json={
            "sender_account_id": "alice-checking",
            "recipient_account_id": "bob-checking",
            "amount_cents": 1000,
        },
    )
    assert own_transfer.status_code == 201
    assert _balances(database) == {
        "alice-checking": 9000,
        "bob-checking": 6000,
    }


def test_transfer_rejects_recipient_balance_overflow(app_client, auth_headers):
    database = app_client.application.config["DATABASE"]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE accounts SET balance_cents = ? WHERE id = ?",
            (2**63 - 500, "bob-checking"),
        )
    before = _balances(database)

    response = app_client.post(
        "/transfers",
        headers=auth_headers("alice"),
        json={
            "sender_account_id": "alice-checking",
            "recipient_account_id": "bob-checking",
            "amount_cents": 1000,
        },
    )

    assert response.status_code == 409
    assert _balances(database) == before
