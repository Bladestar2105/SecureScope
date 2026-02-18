const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const logger = require('../services/logger');

const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, '..', 'database', 'securescope.db');

let db;

function getDatabase() {
    if (!db) {
        db = new Database(DB_PATH);
        db.pragma('journal_mode = WAL');
        db.pragma('foreign_keys = ON');
        db.pragma('busy_timeout = 30000'); // Wait up to 30s if DB is locked by worker
        db.pragma('wal_autocheckpoint = 1000');
    }
    return db;
}

function initializeDatabase() {
    const database = getDatabase();

    // Create users table
    database.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            force_password_change BOOLEAN DEFAULT 0
        )
    `);

    // Create scans table
    database.exec(`
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
        )
    `);

    // Create scan_results table
    database.exec(`
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
        )
    `);

    // Create audit_log table
    database.exec(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Create roles table for RBAC
    database.exec(`
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            permissions TEXT NOT NULL DEFAULT '[]',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Create user_roles junction table
    database.exec(`
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            assigned_by INTEGER,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(id)
        )
    `);

    // Create vulnerabilities knowledge base table
    database.exec(`
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
        )
    `);

    // scan_vulnerabilities table is now created later with CVE-based schema

    // Create scheduled_scans table
    database.exec(`
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
        )
    `);

    // Create notification_settings table
    database.exec(`
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
        )
    `);

    // ===== Fingerprinting Database =====
    database.exec(`
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
        )
    `);

    // Enhanced scan results with fingerprinting
    database.exec(`
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
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id)
        )
    `);

    // ===== Scan Vulnerabilities (CVE matches from Nmap service detection) =====
    database.exec(`
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
        )
    `);

    // ===== Exploit Database =====
    database.exec(`
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
        )
    `);

    // Exploit-to-scan mapping
    database.exec(`
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
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (exploit_id) REFERENCES exploits(id)
        )
    `);

    // ===== Attack Chains =====
    database.exec(`
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
        )
    `);

    // Attack Chain Executions
    database.exec(`
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
        )
    `);

    // ===== Security Audit Reports =====
    database.exec(`
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
        )
    `);

    // Audit Findings
    database.exec(`
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
        )
    `);

    // ===== Credential Vault =====
    database.exec(`
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
        )
    `);

    // Credential usage log
    database.exec(`
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
        )
    `);

    // ===== CVE Entries (from cvelistV5) =====
    database.exec(`
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
        )
    `);

    // ===== Database Update Tracking =====
    database.exec(`
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
        )
    `);

    // Create indexes for performance
    database.exec(`
        CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip_address);
        CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_port ON vulnerabilities(port);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service ON vulnerabilities(service);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_scan ON scan_vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user ON scheduled_scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled ON scheduled_scans(enabled);
        CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
        CREATE INDEX IF NOT EXISTS idx_fingerprints_port ON fingerprints(port);
        CREATE INDEX IF NOT EXISTS idx_fingerprints_service ON fingerprints(service_name);
        CREATE INDEX IF NOT EXISTS idx_scan_fingerprints_scan ON scan_fingerprints(scan_id);
        CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id);
        CREATE INDEX IF NOT EXISTS idx_exploits_service ON exploits(service_name);
        CREATE INDEX IF NOT EXISTS idx_exploits_port ON exploits(port);
        CREATE INDEX IF NOT EXISTS idx_scan_exploits_scan ON scan_exploits(scan_id);
        CREATE INDEX IF NOT EXISTS idx_attack_chains_enabled ON attack_chains(enabled);
        CREATE INDEX IF NOT EXISTS idx_attack_executions_scan ON attack_chain_executions(scan_id);
        CREATE INDEX IF NOT EXISTS idx_security_audits_scan ON security_audits(scan_id);
        CREATE INDEX IF NOT EXISTS idx_audit_findings_audit ON audit_findings(audit_id);
        CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(created_by);
        CREATE INDEX IF NOT EXISTS idx_credential_usage_cred ON credential_usage_log(credential_id);
        CREATE INDEX IF NOT EXISTS idx_db_update_log_type ON db_update_log(database_type);
        CREATE INDEX IF NOT EXISTS idx_cve_entries_severity ON cve_entries(severity);
        CREATE INDEX IF NOT EXISTS idx_cve_entries_published ON cve_entries(date_published);
        CREATE INDEX IF NOT EXISTS idx_cve_entries_state ON cve_entries(state);
        CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_result ON scan_vulnerabilities(scan_result_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_cve ON scan_vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_scan_results_service ON scan_results(service_product);
    `);

    // Migrate existing scan_results table - add new columns if missing
    try {
        const cols = database.prepare("PRAGMA table_info(scan_results)").all().map(c => c.name);
        if (!cols.includes('service_product')) {
            database.exec("ALTER TABLE scan_results ADD COLUMN service_product TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN service_version TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN service_extra TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN service_cpe TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN banner TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN os_name TEXT");
            database.exec("ALTER TABLE scan_results ADD COLUMN os_accuracy INTEGER DEFAULT 0");
            logger.info('Migrated scan_results table with service detection columns');
        }
    } catch (migErr) {
        // Columns already exist or table doesn't exist yet - both are fine
    }

    // Seed default roles
    const adminRole = database.prepare('SELECT id FROM roles WHERE name = ?').get('admin');
    if (!adminRole) {
        database.prepare(
            "INSERT INTO roles (name, description, permissions) VALUES (?, ?, ?)"
        ).run('admin', 'Vollzugriff auf alle Funktionen', JSON.stringify([
            'scan:start', 'scan:stop', 'scan:view', 'scan:export', 'scan:delete',
            'schedule:create', 'schedule:edit', 'schedule:delete', 'schedule:view',
            'users:create', 'users:edit', 'users:delete', 'users:view',
            'settings:view', 'settings:edit', 'vulnerabilities:view', 'vulnerabilities:edit'
        ]));
        database.prepare(
            "INSERT INTO roles (name, description, permissions) VALUES (?, ?, ?)"
        ).run('analyst', 'Kann Scans durchführen und Ergebnisse einsehen', JSON.stringify([
            'scan:start', 'scan:stop', 'scan:view', 'scan:export',
            'schedule:view', 'vulnerabilities:view'
        ]));
        database.prepare(
            "INSERT INTO roles (name, description, permissions) VALUES (?, ?, ?)"
        ).run('viewer', 'Nur Lesezugriff auf Scan-Ergebnisse', JSON.stringify([
            'scan:view', 'schedule:view', 'vulnerabilities:view'
        ]));
        logger.info('Default roles created (admin, analyst, viewer)');
    }

    // Create default admin user if not exists
    const adminUser = database.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (!adminUser) {
        const saltRounds = 10;
        const passwordHash = bcrypt.hashSync('admin', saltRounds);
        const result = database.prepare(
            'INSERT INTO users (username, password_hash, force_password_change) VALUES (?, ?, ?)'
        ).run('admin', passwordHash, 1);

        // Assign admin role
        const adminRoleId = database.prepare('SELECT id FROM roles WHERE name = ?').get('admin');
        if (adminRoleId) {
            database.prepare(
                'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)'
            ).run(result.lastInsertRowid, adminRoleId.id);
        }
        logger.info('Default admin user created (username: admin, password: admin)');
    }

    // Seed functions removed - only real data from external sources will be used

    // Seed functions removed - only real data from external sources will be used

    logger.info('Database initialized successfully');
    return database;
}

function closeDatabase() {
    if (db) {
        db.close();
        db = null;
        logger.info('Database connection closed');
    }
}

module.exports = {
    getDatabase,
    initializeDatabase,
    closeDatabase
};
