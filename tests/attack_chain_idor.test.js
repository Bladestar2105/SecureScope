process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key';

const request = require('supertest');
const { app } = require('../server');
const { initializeDatabase, closeDatabase, getDatabase } = require('../config/database');
const scannerService = require('../services/scanner');
const attackChainService = require('../services/attackChainService');

let server;
let victimAgent;
let attackerAgent;
let victimToken;
let attackerToken;
let scanId;
let chainId;

beforeAll(async () => {
    // Mock scanner execution
    jest.spyOn(scannerService, '_executeScan').mockImplementation(async () => {});

    // Mock attack chain execution to avoid actual exploits
    jest.spyOn(attackChainService, 'executeChain').mockImplementation(async (scanId, chainId, targetIp, targetPort, userId) => {
        return { executionId: 1, status: 'running' };
    });

    initializeDatabase();
    server = app.listen(0);

    const db = getDatabase();
    const bcrypt = require('bcrypt');
    const hash = await bcrypt.hash('password123', 10);

    // Create Victim
    db.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)").run('victim', hash);
    const victimUser = db.prepare("SELECT id FROM users WHERE username = 'victim'").get();

    // Create Attacker
    db.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)").run('attacker', hash);
    const attackerUser = db.prepare("SELECT id FROM users WHERE username = 'attacker'").get();

    // Get Analyst Role
    const analystRole = db.prepare("SELECT id FROM roles WHERE name = 'analyst'").get();

    // Assign Analyst role to both
    db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)").run(victimUser.id, analystRole.id);
    db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)").run(attackerUser.id, analystRole.id);

    // Setup Agents
    victimAgent = request.agent(server);
    attackerAgent = request.agent(server);

    // Login Victim
    let res = await victimAgent.get('/api/auth/status');
    let csrf = res.body.csrfToken;
    res = await victimAgent.post('/api/auth/login').set('X-CSRF-Token', csrf).send({ username: 'victim', password: 'password123' });
    victimToken = res.body.csrfToken;

    // Login Attacker
    res = await attackerAgent.get('/api/auth/status');
    csrf = res.body.csrfToken;
    res = await attackerAgent.post('/api/auth/login').set('X-CSRF-Token', csrf).send({ username: 'attacker', password: 'password123' });
    attackerToken = res.body.csrfToken;

    // Victim creates a scan
    // First, verify we are logged in as victim
    res = await victimAgent.get('/api/auth/status');

    // Create scan
    res = await victimAgent.post('/api/scan/start')
        .set('X-CSRF-Token', victimToken)
        .send({ target: '127.0.0.1', scanType: 'quick' });

    if (res.status !== 200) {
        console.error('Failed to create scan:', res.body);
    }
    scanId = res.body.scan.id;

    // Create an attack chain (any user can create, or use default if any)
    chainId = attackChainService.create({
        name: 'Test Chain',
        steps: [{ name: 'Step 1', type: 'recon' }]
    }, victimUser.id);

});

afterAll((done) => {
    jest.restoreAllMocks();
    closeDatabase();
    server.close(done);
});

describe('Attack Chain IDOR', () => {
    test('Attacker should NOT be able to execute attack chain on Victim scan', async () => {
        const res = await attackerAgent
            .post('/api/attack-chains/execute')
            .set('X-CSRF-Token', attackerToken)
            .send({
                scanId: scanId,
                chainId: chainId,
                targetIp: '127.0.0.1'
            });

        // Current vulnerability: expect 200
        // Desired behavior: expect 403
        expect(res.status).toBe(403);
    });

    test('Attacker should NOT be able to auto-attack Victim scan', async () => {
         const res = await attackerAgent
            .post('/api/attack-chains/auto-attack')
            .set('X-CSRF-Token', attackerToken)
            .send({
                scanId: scanId,
                targetIp: '127.0.0.1'
            });

        expect(res.status).toBe(403);
    });
});
