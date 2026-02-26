
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

describe('CVEService.getScanCVESummary', () => {
    let mockPrepare;
    let mockGet;

    beforeEach(() => {
        jest.clearAllMocks();

        mockGet = jest.fn();
        mockPrepare = jest.fn(() => ({ get: mockGet }));

        getDatabase.mockReturnValue({
            prepare: mockPrepare
        });
    });

    test('should execute a single optimized query', () => {
        const scanId = 123;

        // Mock return for the optimized query
        mockGet.mockReturnValue({
            total: 10,
            critical: 1,
            high: 2,
            medium: 3,
            low: 4
        });

        const result = CVEService.getScanCVESummary(scanId);

        // Verify result structure
        expect(result).toEqual({
            total: 10,
            critical: 1,
            high: 2,
            medium: 3,
            low: 4
        });

        // Verify it was called only once (optimization check)
        // If this fails (e.g., called 5 times), it means the optimization is not applied yet.
        expect(mockPrepare).toHaveBeenCalledTimes(1);

        // Verify the query contains the optimization logic
        const query = mockPrepare.mock.calls[0][0];
        expect(query).toContain('COUNT(*)');
        expect(query).toContain('CASE WHEN severity');
    });

    test('should handle database errors gracefully', () => {
        mockPrepare.mockImplementation(() => {
            throw new Error('Database connection failed');
        });

        const result = CVEService.getScanCVESummary(999);

        expect(result).toEqual({
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        });
    });
});
