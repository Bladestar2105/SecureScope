CREATE TABLE IF NOT EXISTS ghdb_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ghdb_id TEXT UNIQUE,
    query TEXT,
    category TEXT,
    short_description TEXT,
    textual_description TEXT,
    date TEXT,
    author TEXT,
    source TEXT DEFAULT 'ghdb',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ghdb_category ON ghdb_entries(category);
CREATE INDEX IF NOT EXISTS idx_ghdb_query ON ghdb_entries(query);
