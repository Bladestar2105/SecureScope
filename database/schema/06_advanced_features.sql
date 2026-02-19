CREATE TABLE IF NOT EXISTS attack_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    strategy TEXT DEFAULT 'standard',
    depth_level INTEGER DEFAULT 2,
    auto_escalate BOOLEAN DEFAULT 0,
    target_services TEXT,
    steps_json TEXT NOT NULL DEFAULT '[]',
    preconditions_json TEXT DEFAULT '[]',
    risk_level TEXT DEFAULT 'medium',
    enabled BOOLEAN DEFAULT 1,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS attack_chain_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL,
    target_ip TEXT NOT NULL,
    target_port INTEGER,
    status TEXT DEFAULT 'pending',
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER DEFAULT 0,
    results_json TEXT DEFAULT '[]',
    findings_json TEXT DEFAULT '[]',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    executed_by INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (chain_id) REFERENCES attack_chains(id),
    FOREIGN KEY (executed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS security_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    audit_type TEXT DEFAULT 'full',
    overall_score REAL DEFAULT 0,
    risk_rating TEXT DEFAULT 'unknown',
    executive_summary TEXT,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    recommendations_json TEXT DEFAULT '[]',
    compliance_json TEXT DEFAULT '{}',
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    generated_by INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    cvss_score REAL,
    affected_asset TEXT,
    affected_port INTEGER,
    affected_service TEXT,
    evidence TEXT,
    remediation TEXT,
    priority INTEGER DEFAULT 3,
    status TEXT DEFAULT 'open',
    FOREIGN KEY (audit_id) REFERENCES security_audits(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    credential_type TEXT NOT NULL DEFAULT 'password',
    username TEXT,
    password_encrypted TEXT,
    ssh_key_encrypted TEXT,
    domain TEXT,
    auth_method TEXT DEFAULT 'password',
    target_scope TEXT,
    description TEXT,
    tags TEXT DEFAULT '[]',
    last_used_at DATETIME,
    is_valid BOOLEAN DEFAULT 1,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id INTEGER NOT NULL,
    scan_id INTEGER,
    target_ip TEXT,
    target_port INTEGER,
    target_service TEXT,
    auth_success BOOLEAN DEFAULT 0,
    details TEXT,
    used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_by INTEGER,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    FOREIGN KEY (used_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notification_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    email_enabled BOOLEAN DEFAULT 0,
    email_address TEXT,
    smtp_host TEXT,
    smtp_port INTEGER DEFAULT 587,
    smtp_secure BOOLEAN DEFAULT 0,
    smtp_user TEXT,
    smtp_pass TEXT,
    notify_scan_complete BOOLEAN DEFAULT 1,
    notify_critical_found BOOLEAN DEFAULT 1,
    notify_scheduled_report BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS db_update_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    database_type TEXT NOT NULL,
    source TEXT NOT NULL,
    entries_before INTEGER DEFAULT 0,
    entries_added INTEGER DEFAULT 0,
    entries_updated INTEGER DEFAULT 0,
    entries_after INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed',
    error_message TEXT,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    triggered_by INTEGER,
    FOREIGN KEY (triggered_by) REFERENCES users(id)
);
