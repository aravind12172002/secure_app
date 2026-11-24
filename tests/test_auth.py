import time

from app.auth import issue_access_token


TEST_SIGNING_KEY = bytes(range(32))


def test_expired_bearer_token_is_rejected(app_client):
    token = issue_access_token(
        "alice",
        TEST_SIGNING_KEY,
        expires_at=int(time.time()) - 1,
    )

    response = app_client.post(
        "/transfers",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "sender_account_id": "alice-checking",
            "recipient_account_id": "bob-checking",
            "amount_cents": 100,
        },
    )

    assert response.status_code == 401
