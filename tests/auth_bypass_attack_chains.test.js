// Set test environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key';

const request = require('supertest');
const { app } = require('../server');
const { initializeDatabase, closeDatabase, getDatabase } = require('../config/database');
const bcrypt = require('bcrypt');

let server;
let agentAttacker;
let agentVictim;
let victimId;
let attackerId;
let executionId;

beforeAll(async () => {
    // Initialize in-memory database
    initializeDatabase();
    const db = getDatabase();

    // Create users manually
    const passwordHash = await bcrypt.hash('password123', 10);

    // Victim User
    const victimRes = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('victim', passwordHash);
    victimId = victimRes.lastInsertRowid;
    const analystRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('analyst');
    db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(victimId, analystRole.id);

    // Attacker User
    const attackerRes = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('attacker', passwordHash);
    attackerId = attackerRes.lastInsertRowid;
    db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(attackerId, analystRole.id);

    // Create Dummy Scan
    const scanRes = db.prepare(`
        INSERT INTO scans (user_id, scan_type, target, status)
        VALUES (?, 'quick', '127.0.0.1', 'completed')
    `).run(victimId);
    const scanId = scanRes.lastInsertRowid;

    // Create Dummy Chain
    const chainRes = db.prepare(`
        INSERT INTO attack_chains (name, created_by)
        VALUES ('Test Chain', ?)
    `).run(victimId);
    const chainId = chainRes.lastInsertRowid;

    // Create Attack Chain Execution (Victim's execution with sensitive session ID)
    const execRes = db.prepare(`
        INSERT INTO attack_chain_executions (scan_id, chain_id, target_ip, status, executed_by, findings_json)
        VALUES (?, ?, '127.0.0.1', 'completed', ?, ?)
    `).run(scanId, chainId, victimId, JSON.stringify([
        {
            type: 'exploit_success',
            category: 'Remote Shell',
            sessionId: 'SECRET_SESSION_ID_12345',
            title: 'Shell obtained'
        }
    ]));
    executionId = execRes.lastInsertRowid;

    server = app.listen(0);
    agentAttacker = request.agent(server);
    agentVictim = request.agent(server);
});

afterAll((done) => {
    closeDatabase();
    server.close(done);
});

async function login(agent, username, password) {
    // Get CSRF token
    const statusRes = await agent.get('/api/auth/status');
    const csrfToken = statusRes.body.csrfToken;

    // Login
    await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({ username, password });

    return csrfToken;
}

describe('Attack Chain Access Control', () => {
    test('Attacker should NOT be able to access Victim execution details', async () => {
        // Login as attacker
        await login(agentAttacker, 'attacker', 'password123');

        // Try to access victim's execution
        const res = await agentAttacker.get(`/api/attack-chains/executions/${executionId}`);

        // EXPECT FAILURE (403)
        expect(res.status).toBe(403);
    });

    test('Attacker should NOT see Victim execution in history', async () => {
        await login(agentAttacker, 'attacker', 'password123');

        const res = await agentAttacker.get('/api/attack-chains/executions/history');

        // Check if victim's execution is in the list
        const found = res.body.executions.find(e => e.id === executionId);
        expect(found).toBeUndefined();
    });

    test('Victim should be able to access their own execution', async () => {
        // Login as victim
        await login(agentVictim, 'victim', 'password123');

        // Try to access own execution
        const res = await agentVictim.get(`/api/attack-chains/executions/${executionId}`);

        expect(res.status).toBe(200);
        expect(res.body.execution).toBeDefined();
        expect(res.body.execution.executed_by).toBe(victimId);
    });
});
