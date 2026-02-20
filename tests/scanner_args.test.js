
// Mock dependencies before requiring ScannerService
jest.mock('ip-cidr', () => {
    const mockIPCIDR = jest.fn();
    mockIPCIDR.isValidCIDR = jest.fn().mockReturnValue(true);
    return { default: mockIPCIDR, isValidCIDR: mockIPCIDR.isValidCIDR };
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

describe('ScannerService._buildNmapArgs', () => {
    let originalGetUid;

    beforeAll(() => {
        originalGetUid = process.getuid;
    });

    afterAll(() => {
        if (originalGetUid) {
            process.getuid = originalGetUid;
        } else {
            delete process.getuid;
        }
    });

    test('should include OS detection flags when root (standard scan)', () => {
        process.getuid = jest.fn().mockReturnValue(0);
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'standard');
        expect(args).toContain('-O');
        expect(args).toContain('--osscan-guess');
    });

    test('should include OS detection flags when root (quick scan)', () => {
        process.getuid = jest.fn().mockReturnValue(0);
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'quick');
        expect(args).toContain('-O');
        expect(args).toContain('--osscan-guess');
        // Also verify version intensity is NOT reduced (should stay 5)
        const intensityIdx = args.indexOf('--version-intensity');
        expect(args[intensityIdx + 1]).toBe('5');
    });

    test('should include OS detection flags when root (custom scan)', () => {
        process.getuid = jest.fn().mockReturnValue(0);
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'custom');
        expect(args).toContain('-O');
        expect(args).toContain('--osscan-guess');
    });

    test('should NOT include OS detection flags when not root (standard scan)', () => {
        process.getuid = jest.fn().mockReturnValue(1000);
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'standard');
        expect(args).not.toContain('-O');
        expect(args).not.toContain('--osscan-guess');
    });

    test('should NOT include OS detection flags when process.getuid is undefined (e.g. Windows)', () => {
        process.getuid = undefined;
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'standard');
        expect(args).not.toContain('-O');
        expect(args).not.toContain('--osscan-guess');
    });
});
