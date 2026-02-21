
const { getDatabase } = require('../config/database');
const scannerService = require('../services/scanner');

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

    test('should correctly compare two scans with overlapping and unique ports', () => {
        const results1 = [
            { ip_address: '192.168.1.1', port: 80, protocol: 'tcp' },
            { ip_address: '192.168.1.1', port: 443, protocol: 'tcp' }
        ];
        const results2 = [
            { ip_address: '192.168.1.1', port: 443, protocol: 'tcp' },
            { ip_address: '192.168.1.1', port: 8080, protocol: 'tcp' }
        ];

        mockDb.all
            .mockReturnValueOnce(results1) // for scan1
            .mockReturnValueOnce(results2); // for scan2

        mockDb.get
            .mockReturnValueOnce({ id: 1, target: '192.168.1.1' }) // for scan1 info
            .mockReturnValueOnce({ id: 2, target: '192.168.1.1' }); // for scan2 info

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.scan1.resultCount).toBe(2);
        expect(comparison.scan2.resultCount).toBe(2);
        expect(comparison.comparison.newPorts).toBe(1); // 8080
        expect(comparison.comparison.closedPorts).toBe(1); // 80
        expect(comparison.comparison.unchangedPorts).toBe(1); // 443
        expect(comparison.comparison.onlyInScan1).toHaveLength(1);
        expect(comparison.comparison.onlyInScan1[0].port).toBe(80);
        expect(comparison.comparison.onlyInScan2).toHaveLength(1);
        expect(comparison.comparison.onlyInScan2[0].port).toBe(8080);
        expect(comparison.comparison.inBoth).toHaveLength(1);
        expect(comparison.comparison.inBoth[0].port).toBe(443);
    });

    test('should correctly handle identical scans', () => {
        const results = [
            { ip_address: '192.168.1.1', port: 80, protocol: 'tcp' }
        ];

        mockDb.all
            .mockReturnValueOnce(results)
            .mockReturnValueOnce(results);

        mockDb.get
            .mockReturnValueOnce({ id: 1 })
            .mockReturnValueOnce({ id: 2 });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.newPorts).toBe(0);
        expect(comparison.comparison.closedPorts).toBe(0);
        expect(comparison.comparison.unchangedPorts).toBe(1);
    });

    test('should correctly handle completely different scans', () => {
        const results1 = [{ ip_address: '192.168.1.1', port: 80 }];
        const results2 = [{ ip_address: '192.168.1.2', port: 80 }];

        mockDb.all
            .mockReturnValueOnce(results1)
            .mockReturnValueOnce(results2);

        mockDb.get
            .mockReturnValueOnce({ id: 1 })
            .mockReturnValueOnce({ id: 2 });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.newPorts).toBe(1);
        expect(comparison.comparison.closedPorts).toBe(1);
        expect(comparison.comparison.unchangedPorts).toBe(0);
    });

    test('should handle empty scans', () => {
        mockDb.all
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]);

        mockDb.get
            .mockReturnValueOnce({ id: 1 })
            .mockReturnValueOnce({ id: 2 });

        const comparison = scannerService.compareScans(1, 2);

        expect(comparison.comparison.newPorts).toBe(0);
        expect(comparison.comparison.closedPorts).toBe(0);
        expect(comparison.comparison.unchangedPorts).toBe(0);
    });

    test('should handle non-existent scans', () => {
        mockDb.all
            .mockReturnValueOnce([])
            .mockReturnValueOnce([]);

        mockDb.get
            .mockReturnValueOnce(null)
            .mockReturnValueOnce(null);

        const comparison = scannerService.compareScans(99, 100);

        expect(comparison.scan1.info).toBeNull();
        expect(comparison.scan2.info).toBeNull();
    });
});
