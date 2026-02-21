const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Test for configurable salt in CredentialService
 */
describe('CredentialService Security Fix', () => {
    let CredentialService;
    let security;
    const originalEnv = process.env;

    beforeEach(() => {
        jest.resetModules();
        process.env = { ...originalEnv };
        process.env.NODE_ENV = 'development';

        // Mock database
        jest.mock('../config/database', () => ({
            getDatabase: jest.fn().mockReturnValue({
                prepare: jest.fn().mockReturnValue({
                    all: jest.fn().mockReturnValue([]),
                    get: jest.fn().mockReturnValue({}),
                    run: jest.fn().mockReturnValue({ lastInsertRowid: 1 })
                })
            })
        }));
        // Mock logger
        jest.mock('../services/logger', () => ({
            info: jest.fn(),
            error: jest.fn(),
            audit: jest.fn()
        }));
    });

    afterAll(() => {
        process.env = originalEnv;
    });

    test('should use default salt in development if not provided', () => {
        delete process.env.CREDENTIAL_SALT;
        security = require('../config/security');
        expect(security.CREDENTIAL_SALT).toBe('securescope-salt-v1');
    });

    test('should use provided CREDENTIAL_SALT from environment', () => {
        process.env.CREDENTIAL_SALT = 'my-custom-salt-12345678901234567890';
        security = require('../config/security');
        expect(security.CREDENTIAL_SALT).toBe('my-custom-salt-12345678901234567890');
    });

    test('should generate random salt in production if salt is insecure', () => {
        process.env.NODE_ENV = 'production';
        process.env.CREDENTIAL_SALT = 'securescope-salt-v1'; // Insecure
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        security = require('../config/security');

        expect(security.CREDENTIAL_SALT).not.toBe('securescope-salt-v1');
        expect(security.CREDENTIAL_SALT.length).toBeGreaterThan(16);
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Insecure CREDENTIAL_SALT provided'));

        consoleSpy.mockRestore();
    });

    test('CredentialService should use CREDENTIAL_SALT from security config', () => {
        process.env.CREDENTIAL_SALT = 'test-salt';
        security = require('../config/security');
        CredentialService = require('../services/credentialService');

        // We can't easily check the private ENCRYPTION_KEY directly without modifying the code
        // but we can verify it's importing the right thing.
        const content = fs.readFileSync(path.join(__dirname, '..', 'services', 'credentialService.js'), 'utf8');
        expect(content).toContain('const { CREDENTIAL_SECRET, CREDENTIAL_SALT } = require(\'../config/security\')');
        expect(content).toContain('CREDENTIAL_SALT, 32');
        expect(content).not.toContain("'securescope-salt-v1'");
    });
});
