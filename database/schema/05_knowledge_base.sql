CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    cvss_score REAL,
    references_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id TEXT PRIMARY KEY,
    state TEXT DEFAULT 'PUBLISHED',
    date_published TEXT,
    date_updated TEXT,
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    affected_products TEXT,
    references_json TEXT,
    source_data_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exploit_db_id TEXT,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    platform TEXT,
    exploit_type TEXT DEFAULT 'remote',
    service_name TEXT,
    service_version_min TEXT,
    service_version_max TEXT,
    port INTEGER,
    severity TEXT DEFAULT 'high',
    cvss_score REAL,
    reliability TEXT DEFAULT 'unknown',
    source TEXT DEFAULT 'local',
    source_url TEXT,
    exploit_code TEXT,
    verified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT NOT NULL,
    version_pattern TEXT,
    banner_pattern TEXT,
    os_family TEXT,
    os_version TEXT,
    cpe TEXT,
    description TEXT,
    confidence INTEGER DEFAULT 80,
    source TEXT DEFAULT 'local',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
