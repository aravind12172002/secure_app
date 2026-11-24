import os
import sqlite3
from pathlib import Path

from flask import Flask, current_app, g


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get(
            "APP_DATABASE",
            os.path.join(app.instance_path, "ledger.sqlite3"),
        ),
        TOKEN_SIGNING_KEY=os.environ.get("APP_TOKEN_SIGNING_KEY"),
    )
    if test_config:
        app.config.update(test_config)
    signing_key = app.config["TOKEN_SIGNING_KEY"]
    if isinstance(signing_key, str):
        signing_key = signing_key.encode("utf-8")
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise RuntimeError(
            "Set APP_TOKEN_SIGNING_KEY to at least 32 bytes before starting the API."
        )
    app.config["TOKEN_SIGNING_KEY"] = signing_key

    database_path = app.config["DATABASE"]
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        schema_path = Path(__file__).with_name("schema.sql")
        connection.executescript(schema_path.read_text(encoding="utf-8"))

    from app.ledger import ledger

    app.register_blueprint(ledger)
    app.teardown_appcontext(close_db)
    return app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            isolation_level=None,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()
