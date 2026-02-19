// Set test environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key';

const request = require('supertest');
const { app } = require('../server');
const { initializeDatabase, closeDatabase, getDatabase } = require('../config/database');
const scannerService = require('../services/scanner');
const NmapParser = require('../services/nmapParser');

let server;
let agent;

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

async function getCsrfToken(agent) {
    const res = await agent.get('/api/auth/status');
    return res.body.csrfToken;
}

// ============================================
// Authentication Tests
// ============================================
describe('Authentication', () => {

    describe('POST /api/auth/login', () => {
        test('should reject empty credentials', async () => {
            const token = await getCsrfToken(agent);
            const res = await agent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({});

            expect(res.status).toBe(400);
            expect(res.body.error).toBeDefined();
        });

        test('should reject invalid credentials', async () => {
            const token = await getCsrfToken(agent);
            const res = await agent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'wrongpassword' });

            expect(res.status).toBe(401);
            expect(res.body.error).toBeDefined();
        });

        test('should login with default admin credentials', async () => {
            const token = await getCsrfToken(agent);
            const res = await agent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.user).toBeDefined();
            expect(res.body.user.username).toBe('admin');
            expect(res.body.user.forcePasswordChange).toBe(true);
            expect(res.body.csrfToken).toBeDefined();
        });

        test('should indicate force password change for default admin', async () => {
            const token = await getCsrfToken(agent);
            const res = await agent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            expect(res.body.user.forcePasswordChange).toBe(true);
        });

        test('should reject username with special characters', async () => {
            const token = await getCsrfToken(agent);
            const res = await agent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: '<script>alert(1)</script>', password: 'test' });

            expect(res.status).toBe(400);
        });
    });

    describe('GET /api/auth/status', () => {
        test('should return unauthenticated for new session', async () => {
            const res = await request(server)
                .get('/api/auth/status');

            expect(res.status).toBe(200);
            expect(res.body.authenticated).toBe(false);
            expect(res.body.csrfToken).toBeDefined();
        });

        test('should return authenticated after login', async () => {
            // Login first
            const loginAgent = request.agent(server);
            const token = await getCsrfToken(loginAgent);
            await loginAgent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            const res = await loginAgent
                .get('/api/auth/status');

            expect(res.status).toBe(200);
            expect(res.body.authenticated).toBe(true);
            expect(res.body.user.username).toBe('admin');
        });
    });

    describe('POST /api/auth/logout', () => {
        test('should logout successfully', async () => {
            const loginAgent = request.agent(server);

            // Login
            const token = await getCsrfToken(loginAgent);
            await loginAgent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            // Logout (requires CSRF token too?)
            // Usually logout requires CSRF token.
            // Let's get a fresh token or use existing one.
            // But after login, the token might have rotated?
            // The response from login contains a new csrfToken if rotated.
            // But doubleCsrf usually keeps it valid unless rotated.
            // Let's get status again to be sure.
            const statusRes = await loginAgent.get('/api/auth/status');
            const logoutToken = statusRes.body.csrfToken;

            const res = await loginAgent
                .post('/api/auth/logout')
                .set('X-CSRF-Token', logoutToken);

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);

            // Verify logged out
            const verifyRes = await loginAgent
                .get('/api/auth/status');

            expect(verifyRes.body.authenticated).toBe(false);
        });
    });

    describe('POST /api/auth/change-password', () => {
        test('should reject unauthenticated password change', async () => {
            // Even unauthenticated needs CSRF token to pass the middleware check?
            // Yes, middleware is applied.
            // But checking unauthenticated logic happens inside requireAuth which is run...
            // Wait, middleware order:
            // 1. sessionTimeout
            // 2. csrfProtection
            // 3. route handler -> requireAuth

            // So CSRF check happens BEFORE requireAuth.
            // So we need a valid CSRF token even to get a 401.

            const tempAgent = request.agent(server);
            const token = await getCsrfToken(tempAgent);

            const res = await tempAgent
                .post('/api/auth/change-password')
                .set('X-CSRF-Token', token)
                .send({
                    currentPassword: 'admin',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                });

            expect(res.status).toBe(401);
        });

        test('should reject mismatched passwords', async () => {
            const loginAgent = request.agent(server);

            // Login
            const token = await getCsrfToken(loginAgent);
            const loginRes = await loginAgent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            // The login response returns a NEW csrfToken which should be used.
            const csrfToken = loginRes.body.csrfToken;

            const res = await loginAgent
                .post('/api/auth/change-password')
                .set('X-CSRF-Token', csrfToken)
                .send({
                    currentPassword: 'admin',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'DifferentPass123!'
                });

            expect(res.status).toBe(400);
        });

        test('should reject short passwords', async () => {
            const loginAgent = request.agent(server);

            const token = await getCsrfToken(loginAgent);
            const loginRes = await loginAgent
                .post('/api/auth/login')
                .set('X-CSRF-Token', token)
                .send({ username: 'admin', password: 'admin' });

            const csrfToken = loginRes.body.csrfToken;

            const res = await loginAgent
                .post('/api/auth/change-password')
                .set('X-CSRF-Token', csrfToken)
                .send({
                    currentPassword: 'admin',
                    newPassword: 'short',
                    confirmPassword: 'short'
                });

            expect(res.status).toBe(400);
        });
    });
});

// ============================================
// Scan API Tests
// ============================================
describe('Scan API', () => {

    let authenticatedAgent;
    let csrfToken;

    beforeAll(async () => {
        authenticatedAgent = request.agent(server);

        // Login flow
        const initialToken = await getCsrfToken(authenticatedAgent);

        const loginRes = await authenticatedAgent
            .post('/api/auth/login')
            .set('X-CSRF-Token', initialToken)
            .send({ username: 'admin', password: 'admin' });

        csrfToken = loginRes.body.csrfToken;

        // Change password to satisfy forcePasswordChange requirement
        await authenticatedAgent
            .post('/api/auth/change-password')
            .set('X-CSRF-Token', csrfToken)
            .send({
                currentPassword: 'admin',
                newPassword: 'NewPassword123!',
                confirmPassword: 'NewPassword123!'
            });

        // After password change, we might need a new token?
        // Or the existing one is still valid?
        // Let's get a fresh one to be safe.
        const statusRes = await authenticatedAgent.get('/api/auth/status');
        csrfToken = statusRes.body.csrfToken;

    }, 10000); // Increase timeout for setup

    describe('POST /api/scan/start', () => {
        test('should reject unauthenticated scan request', async () => {
            // Need CSRF token even for unauthenticated request check
            const tempAgent = request.agent(server);
            const token = await getCsrfToken(tempAgent);

            const res = await tempAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', token)
                .send({ target: '127.0.0.1', scanType: 'quick' });

            expect(res.status).toBe(401);
        });

        test('should reject scan without target', async () => {
            const res = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ scanType: 'quick' });

            expect(res.status).toBe(400);
        });

        test('should reject invalid scan type', async () => {
            const res = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ target: '127.0.0.1', scanType: 'invalid' });

            expect(res.status).toBe(400);
        });

        test('should reject invalid IP address', async () => {
            const res = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ target: 'not-an-ip', scanType: 'quick' });

            expect(res.status).toBe(400);
        });

        test('should reject external IP when ALLOW_EXTERNAL_SCANS is false', async () => {
            const res = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ target: '8.8.8.8', scanType: 'quick' });

            expect(res.status).toBe(400);
            expect(res.body.error).toContain('privat');
        });

        test('should accept valid private IP scan', async () => {
            const res = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ target: '127.0.0.1', scanType: 'quick' });

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.scan).toBeDefined();
            expect(res.body.scan.id).toBeDefined();
        });
    });

    describe('GET /api/scan/history', () => {
        test('should reject unauthenticated history request', async () => {
            const res = await request(server)
                .get('/api/scan/history');

            expect(res.status).toBe(401);
        });

        test('should return scan history', async () => {
            const res = await authenticatedAgent
                .get('/api/scan/history');

            expect(res.status).toBe(200);
            expect(res.body.scans).toBeDefined();
            expect(Array.isArray(res.body.scans)).toBe(true);
            expect(res.body.pagination).toBeDefined();
        });
    });

    describe('GET /api/scan/status/:id', () => {
        test('should return scan status', async () => {
            // Start a scan first
            const scanRes = await authenticatedAgent
                .post('/api/scan/start')
                .set('X-CSRF-Token', csrfToken)
                .send({ target: '127.0.0.1', scanType: 'quick' });

            const scanId = scanRes.body.scan.id;

            const res = await authenticatedAgent
                .get(`/api/scan/status/${scanId}`);

            expect(res.status).toBe(200);
            expect(res.body.scan).toBeDefined();
            expect(res.body.scan.id).toBe(scanId);
        });

        test('should return 404 for non-existent scan', async () => {
            const res = await authenticatedAgent
                .get('/api/scan/status/99999');

            expect(res.status).toBe(404);
        });
    });
});

// ============================================
// Input Validation Tests
// ============================================
describe('Input Validation', () => {

    const scannerService = require('../services/scanner');
    const ScannerService = scannerService.constructor;

    test('should validate correct IPv4 addresses', () => {
        expect(ScannerService.isValidIP('192.168.1.1')).toBe(true);
        expect(ScannerService.isValidIP('10.0.0.1')).toBe(true);
        expect(ScannerService.isValidIP('127.0.0.1')).toBe(true);
        expect(ScannerService.isValidIP('255.255.255.255')).toBe(true);
    });

    test('should reject invalid IPv4 addresses', () => {
        expect(ScannerService.isValidIP('256.1.1.1')).toBe(false);
        expect(ScannerService.isValidIP('abc.def.ghi.jkl')).toBe(false);
        expect(ScannerService.isValidIP('192.168.1')).toBe(false);
        expect(ScannerService.isValidIP('')).toBe(false);
        expect(ScannerService.isValidIP('192.168.1.1.1')).toBe(false);
    });

    test('should identify private IP ranges', () => {
        expect(ScannerService.isPrivateIP('10.0.0.1')).toBe(true);
        expect(ScannerService.isPrivateIP('172.16.0.1')).toBe(true);
        expect(ScannerService.isPrivateIP('172.31.255.255')).toBe(true);
        expect(ScannerService.isPrivateIP('192.168.1.1')).toBe(true);
        expect(ScannerService.isPrivateIP('127.0.0.1')).toBe(true);
    });

    test('should identify public IP ranges', () => {
        expect(ScannerService.isPrivateIP('8.8.8.8')).toBe(false);
        expect(ScannerService.isPrivateIP('1.1.1.1')).toBe(false);
        expect(ScannerService.isPrivateIP('172.32.0.1')).toBe(false);
        expect(ScannerService.isPrivateIP('11.0.0.1')).toBe(false);
    });

    test('should validate port specifications', () => {
        expect(ScannerService.validatePorts('80').valid).toBe(true);
        expect(ScannerService.validatePorts('22,80,443').valid).toBe(true);
        expect(ScannerService.validatePorts('1-1024').valid).toBe(true);
        expect(ScannerService.validatePorts('22,80,443,1-1024').valid).toBe(true);
    });

    test('should reject invalid port specifications', () => {
        expect(ScannerService.validatePorts('0').valid).toBe(false);
        expect(ScannerService.validatePorts('65536').valid).toBe(false);
        expect(ScannerService.validatePorts('abc').valid).toBe(false);
        expect(ScannerService.validatePorts('').valid).toBe(false);
    });

    test('should validate targets correctly', () => {
        expect(ScannerService.validateTarget('192.168.1.1').valid).toBe(true);
        expect(ScannerService.validateTarget('192.168.1.0/24').valid).toBe(true);
        expect(ScannerService.validateTarget('invalid').valid).toBe(false);
        expect(ScannerService.validateTarget('192.168.1.0/16').valid).toBe(false); // Too large
    });

    test('should return correct risk levels', () => {
        expect(NmapParser.getRiskLevel(22, 'open')).toBe('safe');
        expect(NmapParser.getRiskLevel(443, 'open')).toBe('safe');
        expect(NmapParser.getRiskLevel(23, 'open')).toBe('critical');
        expect(NmapParser.getRiskLevel(445, 'open')).toBe('critical');
        expect(NmapParser.getRiskLevel(80, 'open')).toBe('warning');
        expect(NmapParser.getRiskLevel(12345, 'open')).toBe('warning');
        expect(NmapParser.getRiskLevel(80, 'closed')).toBe('info');
    });
});
