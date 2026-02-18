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

    // Create scan_vulnerabilities linking scan results to vulnerabilities
    database.exec(`
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            scan_result_id INTEGER NOT NULL,
            vulnerability_id INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
    `);

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
    `);

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

    // Seed vulnerability knowledge base
    seedVulnerabilities(database);

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

function seedVulnerabilities(database) {
    const count = database.prepare('SELECT COUNT(*) as c FROM vulnerabilities').get();
    if (count.c > 0) return;

    const vulns = [
        { port: 21, service: 'FTP', cve: 'CVE-2011-2523', severity: 'critical', cvss: 9.8,
          title: 'FTP Anonymous Login erlaubt',
          description: 'FTP-Server erlaubt anonymen Zugriff ohne Authentifizierung. Angreifer können Dateien lesen oder hochladen.',
          remediation: 'Deaktivieren Sie anonymen FTP-Zugang. Verwenden Sie SFTP statt FTP.' },
        { port: 21, service: 'FTP', cve: 'CVE-2015-3306', severity: 'critical', cvss: 10.0,
          title: 'ProFTPD mod_copy Schwachstelle',
          description: 'ProFTPD mod_copy erlaubt unauthentifizierten Benutzern das Kopieren von Dateien auf dem Server.',
          remediation: 'Aktualisieren Sie ProFTPD auf die neueste Version. Deaktivieren Sie mod_copy.' },
        { port: 22, service: 'SSH', cve: 'CVE-2023-48795', severity: 'medium', cvss: 5.9,
          title: 'SSH Terrapin Attack',
          description: 'SSH-Verbindungen können durch Prefix-Truncation-Angriff manipuliert werden.',
          remediation: 'Aktualisieren Sie OpenSSH auf Version 9.6 oder höher. Deaktivieren Sie ChaCha20-Poly1305 und CBC-ETM Cipher.' },
        { port: 22, service: 'SSH', cve: 'CVE-2020-15778', severity: 'high', cvss: 7.8,
          title: 'OpenSSH SCP Command Injection',
          description: 'SCP-Befehlsinjektion über manipulierte Dateinamen möglich.',
          remediation: 'Verwenden Sie SFTP statt SCP. Aktualisieren Sie OpenSSH.' },
        { port: 23, service: 'Telnet', cve: 'CVE-2020-10188', severity: 'critical', cvss: 9.8,
          title: 'Telnet unverschlüsselte Kommunikation',
          description: 'Telnet überträgt alle Daten inkl. Passwörter im Klartext. Extrem anfällig für Man-in-the-Middle-Angriffe.',
          remediation: 'Deaktivieren Sie Telnet vollständig. Verwenden Sie SSH als sichere Alternative.' },
        { port: 25, service: 'SMTP', cve: 'CVE-2021-3156', severity: 'high', cvss: 7.5,
          title: 'SMTP Open Relay',
          description: 'SMTP-Server akzeptiert E-Mails von nicht-authentifizierten Absendern für externe Domains.',
          remediation: 'Konfigurieren Sie SMTP-Authentifizierung. Beschränken Sie Relay auf autorisierte Benutzer.' },
        { port: 53, service: 'DNS', cve: 'CVE-2020-1350', severity: 'critical', cvss: 10.0,
          title: 'DNS SigRed Schwachstelle',
          description: 'Windows DNS Server Remote Code Execution über manipulierte DNS-Antworten.',
          remediation: 'Installieren Sie Microsoft-Sicherheitsupdates. Beschränken Sie DNS-Rekursion.' },
        { port: 80, service: 'HTTP', cve: 'CVE-2021-41773', severity: 'high', cvss: 7.5,
          title: 'HTTP ohne Verschlüsselung',
          description: 'Webserver ohne TLS/SSL-Verschlüsselung. Daten werden im Klartext übertragen.',
          remediation: 'Aktivieren Sie HTTPS mit einem gültigen TLS-Zertifikat. Leiten Sie HTTP auf HTTPS um.' },
        { port: 110, service: 'POP3', cve: 'CVE-2019-3462', severity: 'medium', cvss: 6.5,
          title: 'POP3 Klartext-Authentifizierung',
          description: 'POP3 überträgt Anmeldedaten unverschlüsselt.',
          remediation: 'Verwenden Sie POP3S (Port 995) mit TLS-Verschlüsselung.' },
        { port: 111, service: 'RPCBind', cve: 'CVE-2017-8779', severity: 'critical', cvss: 9.8,
          title: 'RPCBind DDoS-Amplification',
          description: 'RPCBind kann für DDoS-Amplification-Angriffe missbraucht werden.',
          remediation: 'Deaktivieren Sie RPCBind oder beschränken Sie den Zugriff per Firewall.' },
        { port: 135, service: 'MSRPC', cve: 'CVE-2003-0352', severity: 'critical', cvss: 10.0,
          title: 'Microsoft RPC DCOM Schwachstelle',
          description: 'Remote Code Execution über Microsoft RPC DCOM Interface.',
          remediation: 'Blockieren Sie Port 135 an der Firewall. Installieren Sie alle Windows-Updates.' },
        { port: 139, service: 'NetBIOS', cve: 'CVE-2017-0143', severity: 'critical', cvss: 9.8,
          title: 'NetBIOS Session Service exponiert',
          description: 'NetBIOS ermöglicht Netzwerk-Enumeration und potenzielle Angriffe.',
          remediation: 'Deaktivieren Sie NetBIOS über TCP/IP. Blockieren Sie Port 139 an der Firewall.' },
        { port: 443, service: 'HTTPS', cve: 'CVE-2014-0160', severity: 'high', cvss: 7.5,
          title: 'Heartbleed (OpenSSL)',
          description: 'OpenSSL Heartbleed ermöglicht das Auslesen von Speicherinhalten des Servers.',
          remediation: 'Aktualisieren Sie OpenSSL auf Version 1.0.1g oder höher. Erneuern Sie TLS-Zertifikate.' },
        { port: 445, service: 'SMB', cve: 'CVE-2017-0144', severity: 'critical', cvss: 9.8,
          title: 'EternalBlue (MS17-010)',
          description: 'SMBv1 Remote Code Execution. Wurde von WannaCry-Ransomware ausgenutzt.',
          remediation: 'Deaktivieren Sie SMBv1. Installieren Sie MS17-010 Patch. Blockieren Sie Port 445 extern.' },
        { port: 445, service: 'SMB', cve: 'CVE-2020-0796', severity: 'critical', cvss: 10.0,
          title: 'SMBGhost Schwachstelle',
          description: 'SMBv3 Compression Remote Code Execution ohne Authentifizierung.',
          remediation: 'Installieren Sie KB4551762. Deaktivieren Sie SMBv3 Compression.' },
        { port: 1433, service: 'MSSQL', cve: 'CVE-2020-0618', severity: 'critical', cvss: 8.8,
          title: 'Microsoft SQL Server exponiert',
          description: 'SQL Server ist direkt aus dem Netzwerk erreichbar. Anfällig für Brute-Force und SQL-Injection.',
          remediation: 'Beschränken Sie den Zugriff per Firewall. Verwenden Sie starke Passwörter und Windows-Authentifizierung.' },
        { port: 3306, service: 'MySQL', cve: 'CVE-2012-2122', severity: 'critical', cvss: 9.8,
          title: 'MySQL Netzwerk-Exposition',
          description: 'MySQL-Datenbank ist direkt aus dem Netzwerk erreichbar.',
          remediation: 'Binden Sie MySQL nur an localhost. Verwenden Sie Firewall-Regeln.' },
        { port: 3389, service: 'RDP', cve: 'CVE-2019-0708', severity: 'critical', cvss: 9.8,
          title: 'BlueKeep RDP Schwachstelle',
          description: 'Remote Desktop Protocol Remote Code Execution ohne Authentifizierung.',
          remediation: 'Installieren Sie Sicherheitsupdates. Aktivieren Sie NLA. Verwenden Sie VPN für RDP-Zugriff.' },
        { port: 5432, service: 'PostgreSQL', cve: 'CVE-2019-9193', severity: 'high', cvss: 7.2,
          title: 'PostgreSQL Netzwerk-Exposition',
          description: 'PostgreSQL-Datenbank ist direkt aus dem Netzwerk erreichbar.',
          remediation: 'Beschränken Sie pg_hba.conf auf vertrauenswürdige IPs. Binden Sie nur an localhost.' },
        { port: 5900, service: 'VNC', cve: 'CVE-2019-15678', severity: 'critical', cvss: 9.8,
          title: 'VNC Remote Access exponiert',
          description: 'VNC-Server ist ohne ausreichende Absicherung erreichbar. Oft schwache oder keine Authentifizierung.',
          remediation: 'Verwenden Sie VPN für VNC-Zugriff. Setzen Sie starke Passwörter. Verwenden Sie SSH-Tunneling.' },
        { port: 6379, service: 'Redis', cve: 'CVE-2022-0543', severity: 'critical', cvss: 10.0,
          title: 'Redis ohne Authentifizierung',
          description: 'Redis-Server ist ohne Passwort erreichbar. Ermöglicht Datenzugriff und Remote Code Execution.',
          remediation: 'Aktivieren Sie requirepass. Binden Sie Redis nur an localhost. Verwenden Sie Firewall-Regeln.' },
        { port: 8080, service: 'HTTP-Alt', cve: 'CVE-2021-44228', severity: 'critical', cvss: 10.0,
          title: 'Alternativer HTTP-Port exponiert',
          description: 'Webserver auf alternativem Port. Häufig Entwicklungs- oder Proxy-Server ohne ausreichende Absicherung.',
          remediation: 'Prüfen Sie den laufenden Dienst. Sichern Sie mit TLS ab. Beschränken Sie den Zugriff.' },
        { port: 27017, service: 'MongoDB', cve: 'CVE-2019-2390', severity: 'critical', cvss: 9.8,
          title: 'MongoDB ohne Authentifizierung',
          description: 'MongoDB ist ohne Authentifizierung aus dem Netzwerk erreichbar.',
          remediation: 'Aktivieren Sie Authentifizierung. Binden Sie MongoDB nur an localhost. Verwenden Sie Firewall-Regeln.' }
    ];

    const stmt = database.prepare(`
        INSERT INTO vulnerabilities (cve_id, port, protocol, service, severity, title, description, remediation, cvss_score)
        VALUES (?, ?, 'tcp', ?, ?, ?, ?, ?, ?)
    `);

    const insertAll = database.transaction((items) => {
        for (const v of items) {
            stmt.run(v.cve, v.port, v.service, v.severity, v.title, v.description, v.remediation, v.cvss);
        }
    });

    insertAll(vulns);
    logger.info(`Seeded ${vulns.length} vulnerability entries`);
}

module.exports = {
    getDatabase,
    initializeDatabase,
    closeDatabase
};