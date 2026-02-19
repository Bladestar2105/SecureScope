
// Set test environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key';

const request = require('supertest');
const { app } = require('../server');
const { initializeDatabase, closeDatabase, getDatabase } = require('../config/database');
const scannerService = require('../services/scanner');

let server;
let agent;
let csrfToken;

beforeAll(async () => {
    // Mock _executeScan to avoid running nmap
    jest.spyOn(scannerService, '_executeScan').mockImplementation(async () => {
        // Do nothing
    });

    // Initialize in-memory database
    initializeDatabase();

    // Start server
    await new Promise((resolve) => {
        server = app.listen(0, () => {
            resolve();
        });
    });

    agent = request.agent(server);

    // Login
    const loginRes = await agent
        .post('/api/auth/login')
        .send({ username: 'admin', password: 'admin' });

    csrfToken = loginRes.body.csrfToken;

    // Change password to satisfy forcePasswordChange requirement
    await agent
        .post('/api/auth/change-password')
        .set('X-CSRF-Token', csrfToken)
        .send({
            currentPassword: 'admin',
            newPassword: 'NewPassword123!',
            confirmPassword: 'NewPassword123!'
        });
});

afterAll((done) => {
    jest.restoreAllMocks();
    closeDatabase();
    server.close(done);
});

describe('Scan Export Security', () => {

    test('should escape CSV injection payloads in export', async () => {
        // 1. Create a scan
        const scanRes = await agent
            .post('/api/scan/start')
            .set('X-CSRF-Token', csrfToken)
            .send({ target: '127.0.0.1', scanType: 'quick' });

        const scanId = scanRes.body.scan.id;
        const db = getDatabase();

        // 2. Insert malicious results manually
        const maliciousPayload = "=cmd|' /C calc'!A0";
        const maliciousBanner = "@SUM(1+1)*cmd|' /C calc'!A0";

        db.prepare(`
            INSERT INTO scan_results (scan_id, ip_address, port, protocol, service, state, risk_level, service_product, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(scanId, '127.0.0.1', 80, 'tcp', 'http', 'open', 'critical', maliciousPayload, maliciousBanner);

        // 3. Export CSV
        const res = await agent
            .get(`/api/scan/export/${scanId}?format=csv`)
            .expect(200);

        const csvContent = res.text;

        // 4. Verify escaping
        // The payload should be prefixed with a single quote or handled safely
        // Current vulnerable output: "http","=cmd|' /C calc'!A0"
        // Expected secure output: "http","'=cmd|' /C calc'!A0"

        // Check service_product
        const hasVulnerableProduct = csvContent.includes(`"${maliciousPayload}"`);
        const hasSecureProduct = csvContent.includes(`"'${maliciousPayload}"`);

        // Check banner
        const hasVulnerableBanner = csvContent.includes(`"${maliciousBanner}"`);
        const hasSecureBanner = csvContent.includes(`"'${maliciousBanner}"`);

        if (hasVulnerableProduct || hasVulnerableBanner) {
            console.error('CSV Content contains vulnerable payload:', csvContent);
        }

        expect(hasSecureProduct).toBe(true);
        expect(hasVulnerableProduct).toBe(false);

        expect(hasSecureBanner).toBe(true);
        expect(hasVulnerableBanner).toBe(false);
    });
});
