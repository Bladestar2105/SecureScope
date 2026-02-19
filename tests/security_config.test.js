/**
 * Tests for security configuration and secret management.
 */

describe('Security Configuration', () => {
    const originalEnv = process.env;

    beforeEach(() => {
        jest.resetModules();
        process.env = { ...originalEnv };
        process.env.NODE_ENV = 'development';
        delete process.env.SESSION_SECRET;
        delete process.env.CSRF_SECRET;
        delete process.env.CREDENTIAL_SECRET;
    });

    afterAll(() => {
        process.env = originalEnv;
    });

    test('should generate random secrets in non-production if missing', () => {
        const security = require('../config/security');
        expect(security.SESSION_SECRET).toBeDefined();
        expect(security.CSRF_SECRET).toBeDefined();
        expect(security.CREDENTIAL_SECRET).toBe(security.SESSION_SECRET);
        expect(security.SESSION_SECRET.length).toBeGreaterThan(16);
    });

    test('should generate random secret in production if SESSION_SECRET is missing', () => {
        process.env.NODE_ENV = 'production';
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        const security = require('../config/security');

        expect(security.SESSION_SECRET).toBeDefined();
        expect(security.SESSION_SECRET.length).toBeGreaterThan(16);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Required environment variable SESSION_SECRET is missing'));

        consoleSpy.mockRestore();
    });

    test('should generate random secret in production if SESSION_SECRET is insecure', () => {
        process.env.NODE_ENV = 'production';
        process.env.SESSION_SECRET = 'fallback-secret-change-me';
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        const security = require('../config/security');

        expect(security.SESSION_SECRET).toBeDefined();
        expect(security.SESSION_SECRET).not.toBe('fallback-secret-change-me');
        expect(security.SESSION_SECRET.length).toBeGreaterThan(16);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Insecure SESSION_SECRET provided'));

        consoleSpy.mockRestore();
    });

    test('should use provided secrets if they are secure', () => {
        process.env.SESSION_SECRET = 'a-very-secure-random-session-secret-12345';
        process.env.CSRF_SECRET = 'another-secure-csrf-secret-67890';
        const security = require('../config/security');
        expect(security.SESSION_SECRET).toBe('a-very-secure-random-session-secret-12345');
        expect(security.CSRF_SECRET).toBe('another-secure-csrf-secret-67890');
    });

    test('should allow insecure secrets in development but warn', () => {
        process.env.NODE_ENV = 'development';
        process.env.SESSION_SECRET = 'fallback-secret-change-me';
        const security = require('../config/security');
        expect(security.SESSION_SECRET).toBe('fallback-secret-change-me');
    });
});
