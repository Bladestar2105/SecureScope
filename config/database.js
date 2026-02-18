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

    // Create indexes for performance
    database.exec(`
        CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip_address);
        CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
    `);

    // Create default admin user if not exists
    const adminUser = database.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (!adminUser) {
        const saltRounds = 10;
        const passwordHash = bcrypt.hashSync('admin', saltRounds);
        database.prepare(
            'INSERT INTO users (username, password_hash, force_password_change) VALUES (?, ?, ?)'
        ).run('admin', passwordHash, 1);
        logger.info('Default admin user created (username: admin, password: admin)');
    }

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