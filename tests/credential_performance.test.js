
const { getDatabase } = require('../config/database');
const CredentialService = require('../services/credentialService');

// Mock dependencies
jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    warn: jest.fn(),
    info: jest.fn(),
    error: jest.fn(),
    audit: jest.fn()
}));

describe('CredentialService Performance Optimization', () => {
    let mockPrepare;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();

        mockPrepare = jest.fn();

        // Setup getDatabase mock return value
        getDatabase.mockReturnValue({
            prepare: mockPrepare
        });
    });

    test('reproduction: measures number of prepare calls in getAll', () => {
        const userId = 1;
        const credentialCount = 10;

        // Create mock credentials
        const credentials = [];
        for (let i = 0; i < credentialCount; i++) {
            credentials.push({
                id: i + 1,
                name: `Cred ${i}`,
                credential_type: 'password',
                username: `user${i}`,
                domain: null,
                auth_method: 'password',
                target_scope: null,
                description: null,
                tags: '[]',
                last_used_at: null,
                is_valid: 1,
                created_at: '2023-01-01',
                updated_at: '2023-01-01',
                password_encrypted: 'encrypted-pass',
                ssh_key_encrypted: null
            });
        }

        // Mock statement behavior
        mockPrepare.mockImplementation((query) => {
            const stmt = {
                all: jest.fn().mockReturnValue([]),
                get: jest.fn().mockReturnValue({}),
                run: jest.fn()
            };

            // If it's the main getAll query, return our mock data
            if (typeof query === 'string' && query.includes('SELECT') && query.includes('FROM credentials WHERE created_by = ?')) {
                stmt.all = jest.fn().mockReturnValue(credentials);
            }

            // For the N+1 queries
            if (typeof query === 'string' && query.includes('password_encrypted FROM credentials WHERE id = ?')) {
                stmt.get = jest.fn().mockReturnValue({ password_encrypted: 'encrypted' });
            }
            if (typeof query === 'string' && query.includes('ssh_key_encrypted FROM credentials WHERE id = ?')) {
                stmt.get = jest.fn().mockReturnValue({ ssh_key_encrypted: null });
            }

            return stmt;
        });

        // Run the service method
        const results = CredentialService.getAll(userId);

        // Analyze calls
        const prepareCalls = mockPrepare.mock.calls.map(call => call[0]);

        console.log(`[DEBUG] Total credentials: ${credentialCount}`);
        console.log(`[DEBUG] Total prepare calls: ${prepareCalls.length}`);

        // In optimized code: 1 main query total -> 1 call
        expect(prepareCalls.length).toBe(1);

        // Also verify the results are as expected
        expect(results.length).toBe(credentialCount);
        expect(results[0].hasPassword).toBe(true);
        expect(results[0].hasSshKey).toBe(false);

        // Ensure secrets are masked/removed
        expect(results[0].password_encrypted).toBeUndefined();
        expect(results[0].ssh_key_encrypted).toBeUndefined();
    });
});
