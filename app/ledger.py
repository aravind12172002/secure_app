import sqlite3

from flask import Blueprint, g, jsonify, request

from app import get_db
from app.auth import requires_auth


ledger = Blueprint("ledger", __name__)
MAX_SQLITE_INTEGER = 2**63 - 1


def _error(message, status):
    return jsonify(error=message), status


@ledger.post("/transfers")
@requires_auth
def create_transfer():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("expected a JSON object", 400)

    sender_id = payload.get("sender_account_id")
    recipient_id = payload.get("recipient_account_id")
    amount = payload.get("amount_cents")
    if (
        not isinstance(sender_id, str)
        or not isinstance(recipient_id, str)
        or type(amount) is not int
        or amount <= 0
    ):
        return _error("invalid transfer details", 400)
    if sender_id == recipient_id:
        return _error("source and destination must differ", 400)

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        sender = db.execute(
            "SELECT owner_id, balance_cents FROM accounts WHERE id = ?",
            (sender_id,),
        ).fetchone()
        if sender is None or sender["owner_id"] != g.user_id:
            db.rollback()
            return _error("source account not found", 404)

        recipient = db.execute(
            "SELECT balance_cents FROM accounts WHERE id = ?",
            (recipient_id,),
        ).fetchone()
        if recipient is None:
            db.rollback()
            return _error("destination account not found", 404)
        if recipient["balance_cents"] > MAX_SQLITE_INTEGER - amount:
            db.rollback()
            return _error("destination balance limit reached", 409)
        if sender["balance_cents"] < amount:
            db.rollback()
            return _error("insufficient funds", 409)

        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?",
            (amount, sender_id),
        )
        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?",
            (amount, recipient_id),
        )
        cursor = db.execute(
            "INSERT INTO transfers (sender_account_id, recipient_account_id, amount_cents) "
            "VALUES (?, ?, ?)",
            (sender_id, recipient_id, amount),
        )
        transfer_id = cursor.lastrowid
        db.commit()
    except Exception:
        db.rollback()
        raise

    return jsonify(transfer_id=transfer_id, status="completed"), 201


@ledger.post("/orders/<order_id>/cancel")
@requires_auth
def cancel_order(order_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        order = db.execute(
            "SELECT owner_id, status FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
        if order is None or order["owner_id"] != g.user_id:
            db.rollback()
            return _error("order not found", 404)
        if order["status"] != "pending":
            db.rollback()
            return _error("only pending orders can be cancelled", 409)

        result = db.execute(
            "UPDATE orders SET status = 'cancelled' "
            "WHERE id = ? AND owner_id = ? AND status = 'pending'",
            (order_id, g.user_id),
        )
        if result.rowcount != 1:
            db.rollback()
            return _error("order state changed; retry the request", 409)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return jsonify(order_id=order_id, status="cancelled"), 200
