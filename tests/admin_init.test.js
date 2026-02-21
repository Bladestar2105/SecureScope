// Set test environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-key';
process.env.INITIAL_ADMIN_USERNAME = 'customadmin';
process.env.INITIAL_ADMIN_PASSWORD = 'custompassword123';

const { initializeDatabase, closeDatabase, getDatabase } = require('../config/database');
const bcrypt = require('bcrypt');

describe('Admin Initialization', () => {
    beforeAll(() => {
        initializeDatabase();
    });

    afterAll(() => {
        closeDatabase();
    });

    test('should create admin user with custom credentials from environment variables', () => {
        const db = getDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get('customadmin');

        expect(user).toBeDefined();
        expect(user.username).toBe('customadmin');

        const passwordMatch = bcrypt.compareSync('custompassword123', user.password_hash);
        expect(passwordMatch).toBe(true);
        expect(user.force_password_change).toBe(1);
    });

    test('should assign admin role to the custom admin user', () => {
        const db = getDatabase();
        const user = db.prepare('SELECT id FROM users WHERE username = ?').get('customadmin');
        const userRole = db.prepare('SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?').get(user.id);

        expect(userRole).toBeDefined();
        expect(userRole.name).toBe('admin');
    });
});
