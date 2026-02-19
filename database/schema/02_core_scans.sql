CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    port_range TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    state TEXT,
    risk_level TEXT DEFAULT 'info',
    service_product TEXT,
    service_version TEXT,
    service_extra TEXT,
    service_cpe TEXT,
    banner TEXT,
    os_name TEXT,
    os_accuracy INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    scan_result_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    cvss_score REAL,
    matched_service TEXT,
    matched_version TEXT,
    match_confidence INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE,
    UNIQUE(scan_id, scan_result_id, cve_id)
);

CREATE TABLE IF NOT EXISTS scan_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    scan_result_id INTEGER NOT NULL,
    detected_service TEXT,
    detected_version TEXT,
    detected_os TEXT,
    detected_os_version TEXT,
    cpe TEXT,
    banner TEXT,
    confidence INTEGER DEFAULT 0,
    fingerprint_id INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
    -- FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id) -- Defined in another file, sqlite allows this if consistent
);

CREATE TABLE IF NOT EXISTS scan_exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    scan_result_id INTEGER NOT NULL,
    exploit_id INTEGER NOT NULL,
    match_confidence INTEGER DEFAULT 50,
    match_reason TEXT,
    tested BOOLEAN DEFAULT 0,
    test_result TEXT,
    tested_at DATETIME,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
    -- FOREIGN KEY (exploit_id) REFERENCES exploits(id)
);
