
const sqlite3 = require('better-sqlite3');
const CVEService = require('../services/cveService');
const { getDatabase } = require('../config/database');

jest.mock('../config/database');
jest.mock('../services/logger');

describe('CVEService Benchmark', () => {
    let db;

    beforeAll(() => {
        db = new sqlite3(':memory:');
        getDatabase.mockReturnValue(db);

        // Setup schema
        db.exec(`
            CREATE TABLE cve_entries (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_products TEXT,
                state TEXT
            );
            CREATE TABLE scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                port INTEGER,
                service TEXT,
                service_product TEXT,
                service_version TEXT,
                service_cpe TEXT,
                banner TEXT,
                state TEXT,
                ip_address TEXT
            );
            CREATE TABLE scan_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                scan_result_id INTEGER,
                cve_id TEXT,
                title TEXT,
                severity TEXT,
                cvss_score REAL,
                matched_service TEXT,
                matched_version TEXT,
                match_confidence INTEGER,
                UNIQUE(scan_result_id, cve_id)
            );
        `);

        // Insert dummy CVEs
        const insertCve = db.prepare('INSERT INTO cve_entries (cve_id, title, severity, cvss_score, affected_products, state) VALUES (?, ?, ?, ?, ?, ?)');
        for (let i = 0; i < 1000; i++) {
            insertCve.run(`CVE-2023-${i}`, `Vulnerability ${i}`, 'high', 7.5, `product_${i % 100}`, 'PUBLISHED');
        }
    });

    test('measure matchCVEs execution time', () => {
        const scanId = 1;
        const insertScanResult = db.prepare('INSERT INTO scan_results (scan_id, service_product, service_cpe, state) VALUES (?, ?, ?, ?)');

        for (let i = 0; i < 50; i++) {
            insertScanResult.run(scanId, `product_${i}`, `cpe:/a:vendor:product_${i}:1.0`, 'open');
        }

        const start = Date.now();
        CVEService.matchCVEs(scanId);
        const end = Date.now();

        console.log(`Execution time for 50 scan results: ${end - start}ms`);

        // Count queries executed - we can use better-sqlite3 trace if supported,
        // but we can also just rely on the fact that it's N+1 in code.
    });
});
