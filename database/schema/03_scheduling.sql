CREATE TABLE IF NOT EXISTS scheduled_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    custom_ports TEXT,
    cron_expression TEXT NOT NULL,
    enabled BOOLEAN DEFAULT 1,
    notify_on_complete BOOLEAN DEFAULT 1,
    notify_on_critical BOOLEAN DEFAULT 1,
    last_run_at DATETIME,
    next_run_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
