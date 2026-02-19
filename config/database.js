const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
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
    const schemaDir = path.join(__dirname, '..', 'database', 'schema');

    if (!fs.existsSync(schemaDir)) {
        logger.error(`Schema directory not found at ${schemaDir}`);
        throw new Error('Database schema directory missing');
    }

    const files = fs.readdirSync(schemaDir).sort();

    for (const file of files) {
        if (file.endsWith('.sql')) {
            logger.info(`Executing schema file: ${file}`);
            const sql = fs.readFileSync(path.join(schemaDir, file), 'utf8');
            database.exec(sql);
        }
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
