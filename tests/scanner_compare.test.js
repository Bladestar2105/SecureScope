
// Mock dependencies
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
jest.mock('ip-cidr', () => {
    return {
        default: jest.fn(),
        isValidCIDR: jest.fn()
    };
});

const scannerService = require('../services/scanner');
const { getDatabase } = require('../config/database');

describe('ScannerService.compareScans', () => {
    let mockDb;

    beforeEach(() => {
        jest.clearAllMocks();
        mockDb = {
            prepare: jest.fn().mockReturnThis(),
            all: jest.fn(),
            get: jest.fn()
        };
        getDatabase.mockReturnValue(mockDb);
    });

    const createMockResult = (ip, port) => ({
        ip_address: ip,
        port: port,
        protocol: 'tcp',
        service: 'http',
        state: 'open',
        risk_level: 'medium',
        service_product: 'Apache',
        service_version: '2.4.41',
        banner: 'Apache/2.4.41 (Ubuntu)'
    });

    test('should correctly compare two identical scans', () => {
        const results = [
            createMockResult('192.168.1.1', 80),
            createMockResult('192.168.1.1', 443)
        ];

        const scanInfo = { id: 1, target: '192.168.1.1', status: 'completed' };

        // Setup mock database responses
        mockDb.all.mockReturnValueOnce(results) // results1
                 .mockReturnValueOnce(results); // results2

        mockDb.get.mockReturnValue(scanInfo);

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.scan1.resultCount).toBe(2);
        expect(comparison.scan2.resultCount).toBe(2);
        expect(comparison.comparison.unchangedPorts).toBe(2);
        expect(comparison.comparison.newPorts).toBe(0);
        expect(comparison.comparison.closedPorts).toBe(0);
        expect(comparison.comparison.inBoth).toHaveLength(2);
        expect(comparison.comparison.onlyInScan1).toHaveLength(0);
        expect(comparison.comparison.onlyInScan2).toHaveLength(0);
    });

    test('should correctly compare two completely different scans', () => {
        const results1 = [
            createMockResult('192.168.1.1', 80)
        ];
        const results2 = [
            createMockResult('192.168.1.2', 443)
        ];

        mockDb.all.mockReturnValueOnce(results1)
                 .mockReturnValueOnce(results2);

        mockDb.get.mockImplementation((id) => ({ id, target: 'target', status: 'completed' }));

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.unchangedPorts).toBe(0);
        expect(comparison.comparison.newPorts).toBe(1);
        expect(comparison.comparison.closedPorts).toBe(1);
        expect(comparison.comparison.onlyInScan1[0].ip_address).toBe('192.168.1.1');
        expect(comparison.comparison.onlyInScan2[0].ip_address).toBe('192.168.1.2');
    });

    test('should correctly compare overlapping scans', () => {
        const results1 = [
            createMockResult('192.168.1.1', 80),
            createMockResult('192.168.1.1', 22)
        ];
        const results2 = [
            createMockResult('192.168.1.1', 80),
            createMockResult('192.168.1.1', 443)
        ];

        mockDb.all.mockReturnValueOnce(results1)
                 .mockReturnValueOnce(results2);

        mockDb.get.mockImplementation((id) => ({ id, target: 'target', status: 'completed' }));

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.unchangedPorts).toBe(1); // Port 80
        expect(comparison.comparison.closedPorts).toBe(1);    // Port 22
        expect(comparison.comparison.newPorts).toBe(1);       // Port 443

        expect(comparison.comparison.inBoth[0].port).toBe(80);
        expect(comparison.comparison.onlyInScan1[0].port).toBe(22);
        expect(comparison.comparison.onlyInScan2[0].port).toBe(443);
    });

    test('should handle empty scans', () => {
        mockDb.all.mockReturnValueOnce([])
                 .mockReturnValueOnce([]);

        mockDb.get.mockReturnValue({ id: 1, status: 'completed' });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.unchangedPorts).toBe(0);
        expect(comparison.comparison.newPorts).toBe(0);
        expect(comparison.comparison.closedPorts).toBe(0);
    });

    test('should handle one empty scan (scan 1 empty, scan 2 has results)', () => {
        const results2 = [createMockResult('192.168.1.1', 80)];

        mockDb.all.mockReturnValueOnce([])
                 .mockReturnValueOnce(results2);

        mockDb.get.mockReturnValue({ id: 1, status: 'completed' });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.unchangedPorts).toBe(0);
        expect(comparison.comparison.newPorts).toBe(1);
        expect(comparison.comparison.closedPorts).toBe(0);
        expect(comparison.comparison.onlyInScan2).toHaveLength(1);
    });

    test('should handle one empty scan (scan 1 has results, scan 2 empty)', () => {
        const results1 = [createMockResult('192.168.1.1', 80)];

        mockDb.all.mockReturnValueOnce(results1)
                 .mockReturnValueOnce([]);

        mockDb.get.mockReturnValue({ id: 1, status: 'completed' });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.unchangedPorts).toBe(0);
        expect(comparison.comparison.newPorts).toBe(0);
        expect(comparison.comparison.closedPorts).toBe(1);
        expect(comparison.comparison.onlyInScan1).toHaveLength(1);
    });
});
