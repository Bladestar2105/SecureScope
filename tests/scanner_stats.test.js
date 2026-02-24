
// Mock dependencies
jest.mock('ip-cidr', () => {
    return {
        default: jest.fn(),
        isValidCIDR: jest.fn()
    };
});

jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));

jest.mock('../services/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    audit: jest.fn()
}));

jest.mock('../services/exploitService', () => ({}));
jest.mock('../services/emailService', () => ({}));
jest.mock('../services/nmapParser', () => ({}));
jest.mock('../services/cveService', () => ({}));

const scannerService = require('../services/scanner');
const { getDatabase } = require('../config/database');

describe('ScannerService.getDashboardStats', () => {
    let mockDb;
    let mockPrepare;
    let mockGet;
    let mockAll;

    beforeEach(() => {
        mockGet = jest.fn();
        mockAll = jest.fn();
        mockPrepare = jest.fn().mockReturnValue({
            get: mockGet,
            all: mockAll
        });
        mockDb = {
            prepare: mockPrepare
        };
        getDatabase.mockReturnValue(mockDb);
    });

    test('should retrieve dashboard stats correctly and use optimized query', () => {
        const userId = 1;

        // Mock return values
        // 1. Total counts query
        mockGet.mockReturnValueOnce({
            totalScans: 10,
            completedScans: 8,
            criticalPorts: 5,
            totalVulnerabilities: 20
        });

        // 2. Active scan query
        mockGet.mockReturnValueOnce({
            id: 101,
            status: 'running',
            target: '192.168.1.1'
        });

        // 3. Recent scans query
        const mockRecentScans = [
            { id: 100, target: '192.168.1.10', result_count: 5, vuln_count: 2 },
            { id: 99, target: '192.168.1.11', result_count: 3, vuln_count: 0 }
        ];
        mockAll.mockReturnValueOnce(mockRecentScans);

        // Execute method
        const stats = scannerService.getDashboardStats(userId);

        // Verify results
        expect(stats).toEqual({
            totalScans: 10,
            completedScans: 8,
            criticalPorts: 5,
            totalVulnerabilities: 20,
            activeScans: 0,
            activeScan: { id: 101, status: 'running', target: '192.168.1.1' },
            recentScans: mockRecentScans
        });

        // Verify database calls
        expect(mockPrepare).toHaveBeenCalledTimes(3);

        // Verify recent scans query structure - Ensure correlated subquery optimization is applied
        const recentScansQuery = mockPrepare.mock.calls[2][0];

        // Check for correlated subqueries
        expect(recentScansQuery).toContain('(SELECT COUNT(*) FROM scan_results WHERE scan_id = s.id)');
        expect(recentScansQuery).toContain('(SELECT COUNT(*) FROM scan_vulnerabilities WHERE scan_id = s.id)');

        // Ensure no JOIN and GROUP BY (the anti-pattern for this case)
        expect(recentScansQuery).not.toContain('LEFT JOIN scan_results sr');
        expect(recentScansQuery).not.toContain('LEFT JOIN scan_vulnerabilities sv');
        expect(recentScansQuery).not.toContain('GROUP BY s.id');
    });
});
