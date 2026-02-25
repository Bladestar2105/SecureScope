
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
    let allCallsCount = 0;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();
        allCallsCount = 0;

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

    test('reproduction: measures number of execution calls', () => {
        const scanId = 123;
        const scanResultsCount = 50;

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
                banner: 'Apache/2.4.41',
                state: 'open'
            });
        }

        // Mock statement behavior
        mockPrepare.mockImplementation((query) => {
            const stmt = {
                get: jest.fn().mockReturnValue({ c: 1 }), // for COUNT(*)
                all: jest.fn().mockImplementation(() => {
                    if (query.includes('FROM cve_entries') && query.includes('LIKE ?')) {
                        allCallsCount++;
                    }
                    return [];
                }),
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

        console.log(`[DEBUG] Total scan results: ${scanResultsCount}`);
        console.log(`[DEBUG] Total execution calls for CVE queries: ${allCallsCount}`);

        // In current unoptimized code:
        // For each result:
        // 1. result.service_cpe exists -> 1 searchTerm -> cpeMatchStmt.all()
        // 2. result.service_product exists -> productMatchStmt.all()
        // Total = 2 calls per result. For 5 results = 10 calls.

        // After optimization, it should be exactly 2 calls regardless of N
        expect(allCallsCount).toBe(2);
    });
});
