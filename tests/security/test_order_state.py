import sqlite3

def _order_status(database, order_id):
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT status FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
    return row[0]


def test_order_cancellation_requires_owner_and_pending_state(
    app_client,
    auth_headers,
):
    database = app_client.application.config["DATABASE"]

    foreign_order = app_client.post(
        "/orders/alice-pending/cancel",
        headers=auth_headers("bob"),
    )
    assert foreign_order.status_code == 404
    assert _order_status(database, "alice-pending") == "pending"

    fulfilled_order = app_client.post(
        "/orders/alice-fulfilled/cancel",
        headers=auth_headers("alice"),
    )
    assert fulfilled_order.status_code == 409
    assert _order_status(database, "alice-fulfilled") == "fulfilled"

    own_pending_order = app_client.post(
        "/orders/alice-pending/cancel",
        headers=auth_headers("alice"),
    )
    assert own_pending_order.status_code == 200
    assert _order_status(database, "alice-pending") == "cancelled"
