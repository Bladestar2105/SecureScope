
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
        // Currently expecting failure as the code doesn't check root yet
        // So checking if it contains them (it currently does always)
        expect(args).toContain('-O');
        expect(args).toContain('--osscan-guess');
    });

    test('should NOT include OS detection flags when not root (standard scan)', () => {
        process.getuid = jest.fn().mockReturnValue(1000);
        const args = scannerService._buildNmapArgs('127.0.0.1', '80', 'standard');
        // This expectation will fail until I fix the code
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
