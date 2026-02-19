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

beforeAll((done) => {
    // Mock _executeScan to avoid running nmap and DB crash during tests
    jest.spyOn(scannerService, '_executeScan').mockImplementation(async () => {
        // Do nothing
    });

    // Initialize in-memory database
    initializeDatabase();
    server = app.listen(0, () => {
        agent = request.agent(server);
        done();
    });
});

afterAll((done) => {
    jest.restoreAllMocks();
    closeDatabase();
    server.close(done);
});

describe('Dashboard API', () => {

    beforeAll(async () => {
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

        // Create some scan data
        await agent
            .post('/api/scan/start')
            .set('X-CSRF-Token', csrfToken)
            .send({ target: '127.0.0.1', scanType: 'quick' });

        await agent
            .post('/api/scan/start')
            .set('X-CSRF-Token', csrfToken)
            .send({ target: '127.0.0.1', scanType: 'standard' });
    });

    test('GET /api/scan/dashboard should return dashboard stats', async () => {
        const res = await agent
            .get('/api/scan/dashboard');

        expect(res.status).toBe(200);
        expect(res.body.totalScans).toBeDefined();
        expect(res.body.recentScans).toBeDefined();
        expect(Array.isArray(res.body.recentScans)).toBe(true);
        expect(res.body.recentScans.length).toBeGreaterThan(0);

        // Verify structure of recent scans
        const scan = res.body.recentScans[0];
        expect(scan.id).toBeDefined();
        expect(scan.result_count).toBeDefined();
        expect(scan.vuln_count).toBeDefined();
    });
});
