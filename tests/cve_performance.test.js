
const { getDatabase } = require('../config/database');
const CVEService = require('../services/cveService');

// Mock dependencies
jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    warn: jest.fn(),
    info: jest.fn(),
    error: jest.fn()
}));

describe('CVEService Performance Optimization', () => {
    let mockPrepare;
    let mockTransaction;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();

        mockPrepare = jest.fn();
        mockTransaction = jest.fn((callback) => (items) => {
            // Execute the transaction callback immediately
            callback(items);
        });

        // Setup getDatabase mock return value
        getDatabase.mockReturnValue({
            prepare: mockPrepare,
            transaction: mockTransaction
        });
    });

    test('reproduction: measures number of prepare calls', () => {
        const scanId = 123;
        const scanResultsCount = 5;

        // Create mock scan results
        const scanResults = [];
        for (let i = 0; i < scanResultsCount; i++) {
            scanResults.push({
                id: i + 1,
                port: 80,
                service: 'http',
                service_product: 'Apache httpd',
                service_version: '2.4.41',
                service_cpe: 'cpe:/a:apache:http_server:2.4.41',
                banner: 'Apache/2.4.41'
            });
        }

        // Mock statement behavior
        mockPrepare.mockImplementation((query) => {
            const stmt = {
                get: jest.fn().mockReturnValue({ c: 1 }), // for COUNT(*)
                all: jest.fn().mockReturnValue([]),       // default empty results
                run: jest.fn()
            };

            // If it's the scan_results query, return our mock data
            if (typeof query === 'string' && query.trim().startsWith('SELECT id, port')) {
                stmt.all = jest.fn().mockReturnValue(scanResults);
            }
            return stmt;
        });

        // Run the service method
        CVEService.matchCVEs(scanId);

        // Analyze calls
        const prepareCalls = mockPrepare.mock.calls.map(call => call[0]);

        // Filter for the specific queries we are optimizing
        // These are the queries inside the loop:
        // 1. SELECT ... FROM cve_entries WHERE affected_products LIKE ?
        // 2. SELECT ... FROM cve_entries WHERE (affected_products LIKE ? OR title LIKE ?)

        const cveQueries = prepareCalls.filter(query =>
            query.includes('FROM cve_entries') &&
            query.includes('LIKE ?')
        );

        console.log(`[DEBUG] Total scan results: ${scanResultsCount}`);
        console.log(`[DEBUG] Total prepare calls for CVE queries: ${cveQueries.length}`);

        // Assertions
        // In unoptimized code: 2 queries prepared per result -> 2 * 5 = 10 calls
        // In optimized code: 2 queries prepared total -> 2 calls

        // We expect optimized behavior now
        // Should be exactly 2 (one for each prepared statement type)
        expect(cveQueries.length).toBe(2);
    });
});
