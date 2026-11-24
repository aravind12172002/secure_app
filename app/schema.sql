CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0)
);

CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_account_id TEXT NOT NULL REFERENCES accounts(id),
    recipient_account_id TEXT NOT NULL REFERENCES accounts(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'processing', 'fulfilled', 'cancelled')
    )
);
