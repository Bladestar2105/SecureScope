
const { getDatabase } = require('../config/database');
const CVEService = require('../services/cveService');
const logger = require('../services/logger');

// Mock dependencies
jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    warn: jest.fn(),
    info: jest.fn(),
    error: jest.fn()
}));

describe('CVEService Query Optimization', () => {
    let mockDb;
    let mockPrepare;
    let mockTransaction;
    let cpeMatchAllSpy;
    let productMatchAllSpy;

    beforeEach(() => {
        jest.clearAllMocks();

        cpeMatchAllSpy = jest.fn().mockReturnValue([]);
        productMatchAllSpy = jest.fn().mockReturnValue([]);

        mockPrepare = jest.fn((query) => {
            if (query.includes('FROM cve_entries') && query.includes('affected_products LIKE ?') && !query.includes('OR title LIKE ?')) {
                // cpeMatchStmt
                return { all: cpeMatchAllSpy };
            }
            if (query.includes('FROM cve_entries') && (query.includes('affected_products LIKE ?') && query.includes('OR title LIKE ?'))) {
                // productMatchStmt
                return { all: productMatchAllSpy };
            }
            if (query.includes('SELECT id, port')) {
                 // scanResults query
                 return { all: jest.fn() };
            }
             if (query.includes('COUNT(*)')) {
                 return { get: jest.fn().mockReturnValue({ c: 1 }) };
            }
            // Default mock
            return {
                get: jest.fn().mockReturnValue({ c: 1 }),
                all: jest.fn().mockReturnValue([]),
                run: jest.fn()
            };
        });

        mockTransaction = jest.fn((callback) => (items) => callback(items));

        mockDb = {
            prepare: mockPrepare,
            transaction: mockTransaction
        };

        getDatabase.mockReturnValue(mockDb);
    });

    test('executes queries only once for identical inputs due to caching', () => {
        const scanId = 123;
        // Create 3 identical scan results
        const scanResults = [
            { id: 1, port: 80, service: 'http', service_product: 'Apache', service_cpe: 'cpe:/a:apache:http_server' },
            { id: 2, port: 8080, service: 'http', service_product: 'Apache', service_cpe: 'cpe:/a:apache:http_server' },
            { id: 3, port: 443, service: 'https', service_product: 'Apache', service_cpe: 'cpe:/a:apache:http_server' }
        ];

        // Mock scanResults query return
        mockPrepare.mockImplementation((query) => {
             if (query.includes('SELECT id, port')) {
                 return { all: jest.fn().mockReturnValue(scanResults) };
            }
            if (query.includes('FROM cve_entries') && query.includes('affected_products LIKE ?') && !query.includes('OR title LIKE ?')) {
                return { all: cpeMatchAllSpy };
            }
            if (query.includes('FROM cve_entries') && (query.includes('affected_products LIKE ?') && query.includes('OR title LIKE ?'))) {
                return { all: productMatchAllSpy };
            }
            if (query.includes('COUNT(*)')) {
                 return { get: jest.fn().mockReturnValue({ c: 1 }) };
            }
            return {
                get: jest.fn().mockReturnValue({ c: 1 }),
                all: jest.fn().mockReturnValue([]),
                run: jest.fn()
            };
        });

        CVEService.matchCVEs(scanId);

        // We expect 1 call because caching should handle the duplicates
        expect(cpeMatchAllSpy).toHaveBeenCalledTimes(1);
        expect(productMatchAllSpy).toHaveBeenCalledTimes(1);
    });
});
