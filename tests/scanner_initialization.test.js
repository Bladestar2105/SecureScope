
const { getDatabase } = require('../config/database');

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

describe('ScannerService Initialization', () => {
    let mockDb;
    let scannerService;

    beforeEach(() => {
        jest.clearAllMocks();
        mockDb = {
            prepare: jest.fn().mockReturnThis(),
            run: jest.fn().mockReturnValue({ changes: 0 })
        };
        getDatabase.mockReturnValue(mockDb);

        // Re-require to get a fresh instance if possible, but it's a singleton.
        // We might need to access the class prototype if we want to test the method in isolation
        // or just rely on the exported instance.
        jest.isolateModules(() => {
            scannerService = require('../services/scanner');
        });
    });

    test('initialize should reset zombie scans', () => {
        // This test expects initialize() to exist and call DB
        // It will fail currently because initialize() doesn't exist
        if (typeof scannerService.initialize !== 'function') {
            throw new Error('scannerService.initialize is not a function');
        }

        scannerService.initialize();

        expect(getDatabase).toHaveBeenCalled();
        expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining("UPDATE scans SET status = 'failed'"));
    });

    test('constructor should NOT reset zombie scans', () => {
         // This test verifies that requiring the module (which invokes constructor)
         // does NOT trigger the DB call.

         jest.isolateModules(() => {
             jest.clearAllMocks();
             require('../services/scanner');
         });

         // Constructor runs immediately on require
         expect(mockDb.prepare).not.toHaveBeenCalledWith(expect.stringContaining("UPDATE scans SET status = 'failed'"));
    });
});
