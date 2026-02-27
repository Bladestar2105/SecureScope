
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
    let mockAll;

    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();

        mockAll = jest.fn().mockReturnValue([]); // Default empty results
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

    test('reproduction: verifies reduction in query executions', () => {
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
                all: mockAll, // Shared mock to spy on calls
                run: jest.fn()
            };

            // If it's the scan_results query, return our mock data
            // We use a new mock function here to separate it from CVE queries
            if (typeof query === 'string' && query.trim().startsWith('SELECT id, port')) {
                stmt.all = jest.fn().mockReturnValue(scanResults);
            }
            return stmt;
        });

        // Run the service method
        CVEService.matchCVEs(scanId);

        // Analyze execution calls
        // We want to count how many times `all()` was called for CVE fetching queries
        // In the original code, this was 2 * scanResultsCount = 10 times
        // In the optimized code, this should be 1 (CPE batch) + 1 (Product batch) = 2 times total
        // (Assuming batch size > 5, which it is)

        // Get all calls to the shared mockAll spy
        const allCalls = mockAll.mock.calls;

        // Filter calls that might be related to CVE fetching (though strictly all calls to this spy are CVE fetches because scanResults query uses a different spy)
        const cveFetchExecutions = allCalls.length;

        console.log(`[DEBUG] Total scan results: ${scanResultsCount}`);
        console.log(`[DEBUG] Total executions of CVE fetch queries: ${cveFetchExecutions}`);

        // Assertions
        // Expect drastically fewer calls than the N+1 scenario
        expect(cveFetchExecutions).toBeLessThan(scanResultsCount);

        // Specifically, we expect exactly 2 calls here (1 for CPEs, 1 for Products) because all 5 items fit in one batch
        // Note: The logic executes `fetchAndCache` for CPEs and Products separately.
        expect(cveFetchExecutions).toBe(2);
    });
});
