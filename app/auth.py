import hashlib
import hmac
import time
from functools import wraps

from flask import current_app, g, jsonify, request


def issue_access_token(user_id, signing_key, expires_at=None):
    if isinstance(signing_key, str):
        signing_key = signing_key.encode("utf-8")
    if expires_at is None:
        expires_at = int(time.time()) + 900
    payload = f"{user_id}.{int(expires_at)}"
    signature = hmac.new(signing_key, payload.encode("utf-8"), hashlib.sha256)
    return f"{payload}.{signature.hexdigest()}"


def _authenticated_user(token, signing_key):
    try:
        user_id, expiry_text, supplied_signature = token.rsplit(".", 2)
        expires_at = int(expiry_text)
    except ValueError:
        return None
    if not user_id or not supplied_signature or expires_at <= int(time.time()):
        return None
    payload = f"{user_id}.{expires_at}"
    expected_signature = hmac.new(
        signing_key,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if hmac.compare_digest(supplied_signature, expected_signature):
        return user_id
    return None


def requires_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return jsonify(error="authentication required"), 401
        user_id = _authenticated_user(
            token,
            current_app.config["TOKEN_SIGNING_KEY"],
        )
        if user_id is None:
            return jsonify(error="invalid bearer token"), 401
        g.user_id = user_id
        return view(*args, **kwargs)

    return wrapped
