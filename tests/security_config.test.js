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
        expect(security.CREDENTIAL_SECRET).not.toBe(security.SESSION_SECRET);
        expect(security.SESSION_SECRET.length).toBe(64); // 32 bytes hex
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
        process.env.SESSION_SECRET = 'a-very-secure-random-session-secret-12345-that-is-long-enough';
        process.env.CSRF_SECRET = 'another-secure-csrf-secret-67890-that-is-also-long-enough';
        const security = require('../config/security');
        expect(security.SESSION_SECRET).toBe('a-very-secure-random-session-secret-12345-that-is-long-enough');
        expect(security.CSRF_SECRET).toBe('another-secure-csrf-secret-67890-that-is-also-long-enough');
    });

    test('should NOT allow insecure secrets in development and generate random instead', () => {
        process.env.NODE_ENV = 'development';
        process.env.SESSION_SECRET = 'fallback-secret-change-me';
        const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

        const security = require('../config/security');

        expect(security.SESSION_SECRET).toBeDefined();
        expect(security.SESSION_SECRET).not.toBe('fallback-secret-change-me');
        expect(security.SESSION_SECRET.length).toBe(64);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Insecure SESSION_SECRET detected in development'));

        consoleSpy.mockRestore();
    });

    test('should reject secrets that are too short even in development', () => {
        process.env.NODE_ENV = 'development';
        process.env.SESSION_SECRET = 'too-short';
        const security = require('../config/security');

        expect(security.SESSION_SECRET.length).toBe(64);
        expect(security.SESSION_SECRET).not.toBe('too-short');
    });

    test('should accept secrets that are long enough and not insecure', () => {
        const secureSecret = 'a-very-long-and-secure-secret-that-is-over-32-characters-long';
        process.env.SESSION_SECRET = secureSecret;
        const security = require('../config/security');

        expect(security.SESSION_SECRET).toBe(secureSecret);
    });
});
