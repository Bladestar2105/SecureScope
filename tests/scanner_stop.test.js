
const { getDatabase } = require('../config/database');
const logger = require('../services/logger');

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

// Mock ip-cidr to avoid issues in environment
jest.mock('ip-cidr', () => {
    return {
        default: jest.fn(),
        isValidCIDR: jest.fn()
    };
}, { virtual: true });

// Mock other services required by ScannerService
jest.mock('../services/exploitService', () => ({}));
jest.mock('../services/emailService', () => ({}));
jest.mock('../services/nmapParser', () => ({}));
jest.mock('../services/cveService', () => ({}));

const scannerService = require('../services/scanner');

describe('ScannerService.stopScan', () => {
    let mockDb;

    beforeEach(() => {
        jest.clearAllMocks();
        jest.useFakeTimers();

        mockDb = {
            prepare: jest.fn().mockReturnThis(),
            get: jest.fn(),
            run: jest.fn()
        };
        getDatabase.mockReturnValue(mockDb);

        // Clear activeScans before each test
        scannerService.activeScans.clear();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    test('should stop an active scan with a running process', () => {
        const scanId = 123;
        const mockProcess = {
            kill: jest.fn()
        };
        const scanControl = {
            aborted: false,
            process: mockProcess
        };

        scannerService.activeScans.set(scanId, scanControl);

        const result = scannerService.stopScan(scanId);

        expect(result).toBe(true);
        expect(scanControl.aborted).toBe(true);
        expect(mockProcess.kill).toHaveBeenCalledWith('SIGTERM');
        expect(logger.info).toHaveBeenCalledWith(expect.stringContaining(`Scan ${scanId} abort requested`));
        expect(logger.audit).toHaveBeenCalledWith('SCAN_ABORTED', { scanId });

        // Fast-forward 5 seconds
        jest.advanceTimersByTime(5000);
        expect(mockProcess.kill).toHaveBeenCalledWith('SIGKILL');
    });

    test('should handle stop scan when process.kill fails', () => {
        const scanId = 456;
        const mockProcess = {
            kill: jest.fn().mockImplementation(() => {
                throw new Error('Kill failed');
            })
        };
        const scanControl = {
            aborted: false,
            process: mockProcess
        };

        scannerService.activeScans.set(scanId, scanControl);

        // Should not throw
        const result = scannerService.stopScan(scanId);

        expect(result).toBe(true);
        expect(scanControl.aborted).toBe(true);
        expect(mockProcess.kill).toHaveBeenCalledWith('SIGTERM');
    });

    test('should stop an active scan without a process', () => {
        const scanId = 789;
        const scanControl = {
            aborted: false,
            process: null
        };

        scannerService.activeScans.set(scanId, scanControl);

        const result = scannerService.stopScan(scanId);

        expect(result).toBe(true);
        expect(scanControl.aborted).toBe(true);
        expect(logger.info).toHaveBeenCalledWith(expect.stringContaining(`Scan ${scanId} abort requested`));
    });

    test('should handle zombie scan (not in memory, but running in DB)', () => {
        const scanId = 101;

        // Mock DB: scan exists and is 'running'
        mockDb.get.mockReturnValue({ status: 'running' });
        mockDb.run.mockReturnValue({ changes: 1 });

        const result = scannerService.stopScan(scanId);

        expect(result).toBe(true);
        expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('SELECT status FROM scans'));
        expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining("UPDATE scans SET status = 'aborted'"));
        expect(logger.info).toHaveBeenCalledWith(expect.stringContaining(`Zombie scan ${scanId} manually aborted`));
        expect(logger.audit).toHaveBeenCalledWith('SCAN_ABORTED_MANUAL', { scanId });
    });

    test('should return false if scan is not active and not running in DB', () => {
        const scanId = 202;

        // Mock DB: scan exists but is already 'completed'
        mockDb.get.mockReturnValue({ status: 'completed' });

        const result = scannerService.stopScan(scanId);

        expect(result).toBe(false);
        expect(mockDb.run).not.toHaveBeenCalled();
    });

    test('should return false if scan does not exist in DB', () => {
        const scanId = 303;

        // Mock DB: scan does not exist
        mockDb.get.mockReturnValue(undefined);

        const result = scannerService.stopScan(scanId);

        expect(result).toBe(false);
    });
});
