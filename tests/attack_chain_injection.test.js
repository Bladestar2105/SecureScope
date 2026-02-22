
// Mocks must be declared before require
jest.mock('../config/database', () => ({
    getDatabase: jest.fn(() => ({
        prepare: jest.fn(() => ({
            get: jest.fn(() => ({
                id: 123,
                title: 'Test Exploit',
                port: 80,
                match_confidence: 90,
                cvss_score: 9.0
            })),
            all: jest.fn(() => [])
        })),
        transaction: jest.fn(fn => fn)
    }))
}));

jest.mock('../services/exploitDbSyncService', () => ({
    getExploitCode: jest.fn(() => ({
        language: 'python',
        code: 'LHOST = "<LHOST>"'
    }))
}));

jest.mock('../services/shellService', () => ({
    startListener: jest.fn(() => 'test_session'),
    isConnected: jest.fn(() => true), // Return true to avoid 5s wait loop
    killSession: jest.fn()
}));

jest.mock('../services/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    audit: jest.fn()
}));

jest.mock('child_process', () => ({
    exec: jest.fn((cmd, opts, cb) => {
        if (typeof opts === 'function') {
            cb = opts;
        }
        if (cb) cb(null, '', '');
        return {
            stdout: { on: jest.fn() },
            stderr: { on: jest.fn() },
            on: jest.fn()
        };
    }),
    spawn: jest.fn()
}));

jest.mock('fs', () => {
    const originalFs = jest.requireActual('fs');
    return {
        ...originalFs,
        writeFileSync: jest.fn(),
        mkdtempSync: jest.fn(() => '/tmp/mock-exploit-dir'),
        rmSync: jest.fn(),
        existsSync: jest.fn(() => true)
    };
});

const AttackChainService = require('../services/attackChainService');
const fs = require('fs');

describe('AttackChainService - Security Injection', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should BLOCK LHOST injection with validation', async () => {
        const maliciousLhost = '127.0.0.1"; import os; os.system("echo RCE"); #';

        const step = {
            type: 'exploit',
            name: 'Malicious Exploit',
            exploitId: 123,
            targetPort: 80
        };

        const params = {
            LHOST: maliciousLhost,
            LPORT: 4444
        };

        // Execute the step and expect it not to throw (or catch the specific error if we throw)
        // Wait, executeStep returns { success: true/false, findings: ... } usually, but assumes success.
        // However, we threw an Error in the code: throw new Error(`Invalid LHOST: ${lhost}`);
        // So we expect this promise to reject.

        // AttackChainService._executeStep catches errors internally and logs them?
        // Let's check the code:
        /*
        try {
            // ...
        } catch (e) {
            logger.error(`Exploit execution failed for ${exploit.id}:`, e);
            findings.push({ type: 'error', ... });
        }
        */
        // Yes, it catches errors and logs them. So it won't throw.

        await AttackChainService._executeStep(step, 1, '192.168.1.100', 80, {}, params);

        // Check if writeFileSync was called with injected content
        const writeCalls = fs.writeFileSync.mock.calls;
        let injectionFound = false;

        for (const call of writeCalls) {
            const content = call[1];
            if (content.includes('import os; os.system("echo RCE");')) {
                injectionFound = true;
                break;
            }
        }

        // It should be false because the error was thrown before writeFileSync
        expect(injectionFound).toBe(false);

        // Optionally verify that the error was logged
        // const logger = require('../services/logger');
        // expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Exploit execution failed'), expect.any(Error));
    }, 10000);
});
