const { initializeDatabase, closeDatabase } = require('../config/database');
const bcrypt = require('bcrypt');
const logger = require('../services/logger');

// Mock logger to avoid cluttering test output
jest.mock('../services/logger');

describe('Admin User Initialization', () => {
    const originalEnv = { ...process.env };

    beforeEach(() => {
        // Clear the cached database instance before each test
        closeDatabase();
        // Reset process.env
        process.env = { ...originalEnv };
        process.env.DATABASE_PATH = ':memory:';
        // Clear mock calls
        jest.clearAllMocks();
    });

    afterEach(() => {
        closeDatabase();
        process.env = originalEnv;
    });

    test('should use default admin/admin when no env vars are set (non-production)', () => {
        process.env.NODE_ENV = 'development';
        delete process.env.INITIAL_ADMIN_USERNAME;
        delete process.env.INITIAL_ADMIN_PASSWORD;

        const db = initializeDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');

        expect(user).toBeDefined();
        expect(user.username).toBe('admin');
        expect(bcrypt.compareSync('admin', user.password_hash)).toBe(true);
    });

    test('should use custom admin credentials from env vars', () => {
        process.env.NODE_ENV = 'development';
        process.env.INITIAL_ADMIN_USERNAME = 'customadmin';
        process.env.INITIAL_ADMIN_PASSWORD = 'custompassword';

        const db = initializeDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get('customadmin');

        expect(user).toBeDefined();
        expect(user.username).toBe('customadmin');
        expect(bcrypt.compareSync('custompassword', user.password_hash)).toBe(true);

        // Ensure default 'admin' was NOT created
        const defaultUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
        expect(defaultUser).toBeUndefined();
    });

    test('should generate random password in production when INITIAL_ADMIN_PASSWORD is missing', () => {
        process.env.NODE_ENV = 'production';
        process.env.INITIAL_ADMIN_USERNAME = 'prodadmin';
        delete process.env.INITIAL_ADMIN_PASSWORD;

        const db = initializeDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get('prodadmin');

        expect(user).toBeDefined();
        expect(user.username).toBe('prodadmin');

        // We don't know the password exactly here without capturing it from the logger,
        // but we know it should NOT be 'admin'
        expect(bcrypt.compareSync('admin', user.password_hash)).toBe(false);

        // Check if logger was called with prominence (using expect.stringContaining)
        // Note: logger.info is called multiple times, we check if ANY call contains the info
        const infoCalls = logger.info.mock.calls.map(call => call[0]);
        const hasGeneratedPasswordMessage = infoCalls.some(msg => typeof msg === 'string' && msg.includes('GENERATED PASSWORD'));

        expect(hasGeneratedPasswordMessage).toBe(true);
    });

    test('should use provided password even in production', () => {
        process.env.NODE_ENV = 'production';
        process.env.INITIAL_ADMIN_USERNAME = 'prodadmin';
        process.env.INITIAL_ADMIN_PASSWORD = 'securepassword123';

        const db = initializeDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get('prodadmin');

        expect(user).toBeDefined();
        expect(user.username).toBe('prodadmin');
        expect(bcrypt.compareSync('securepassword123', user.password_hash)).toBe(true);
    });
});
