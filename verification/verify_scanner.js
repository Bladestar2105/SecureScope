const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Mock Config
const dbPath = path.join(__dirname, 'test.db');
if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
const db = new Database(dbPath);

// Setup Schema
db.exec(`
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY,
        status TEXT,
        started_at DATETIME,
        completed_at DATETIME,
        error_message TEXT,
        user_id INTEGER,
        scan_type TEXT,
        target TEXT,
        port_range TEXT,
        progress INTEGER
    );
`);

// Mock Environment
process.env.DATABASE_PATH = dbPath;

// Insert Zombie Scan
db.prepare("INSERT INTO scans (id, status, target) VALUES (999, 'running', '127.0.0.1')").run();

// Run ScannerService
const scannerService = require('../services/scanner');

// Check if zombie was reset
const zombie = db.prepare('SELECT * FROM scans WHERE id = 999').get();
console.log('Zombie status after init:', zombie.status); // Should be 'failed'

if (zombie.status !== 'failed') {
    console.error('FAILED: Zombie scan was not reset');
    process.exit(1);
}

// Test Manual Stop
// Insert another running scan (simulate active in DB but not in memory)
db.prepare("INSERT INTO scans (id, status, target) VALUES (1000, 'running', '127.0.0.1')").run();
const stopped = scannerService.stopScan(1000);
console.log('Stop result:', stopped); // Should be true

const manualZombie = db.prepare('SELECT * FROM scans WHERE id = 1000').get();
console.log('Manual zombie status:', manualZombie.status); // Should be 'aborted'

if (manualZombie.status !== 'aborted') {
    console.error('FAILED: Manual stop did not update DB');
    process.exit(1);
}

console.log('SUCCESS');
