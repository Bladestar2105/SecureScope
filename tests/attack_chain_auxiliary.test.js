
// Mock dependencies first
const { getDatabase } = require('../config/database');

jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));
jest.mock('../services/exploitService');
jest.mock('../services/logger');
jest.mock('../services/exploitDbSyncService');
jest.mock('../services/shellService');
jest.mock('fs');

// Custom mock for child_process to ensure exec calls callback
jest.mock('child_process', () => ({
    exec: jest.fn((cmd, opts, cb) => {
        if (typeof opts === 'function') {
            cb = opts;
        }
        // Call callback immediately
        if (cb) cb(null, 'stdout', 'stderr');
        return {
            stdout: { on: jest.fn() },
            stderr: { on: jest.fn() },
            on: jest.fn()
        };
    }),
    spawn: jest.fn()
}));

// Also mock winston and daily-rotate-file properly
jest.mock('winston', () => {
    // winston.format(fn) returns a function (Format) that can be instantiated/called
    const format = jest.fn().mockImplementation((fn) => {
        return jest.fn().mockReturnValue({}); // Return a factory function that returns a format object
    });

    format.combine = jest.fn();
    format.timestamp = jest.fn();
    format.json = jest.fn();
    format.printf = jest.fn();
    format.colorize = jest.fn();
    format.simple = jest.fn();
    format.errors = jest.fn();

    class Transport {}

    return {
        format: format,
        transports: {
            Console: jest.fn(),
            File: jest.fn()
        },
        createLogger: jest.fn().mockReturnValue({
            info: jest.fn(),
            error: jest.fn(),
            warn: jest.fn(),
            add: jest.fn(),
            log: jest.fn(),
            audit: jest.fn()
        }),
        Transport: Transport
    };
});

jest.mock('winston-daily-rotate-file', () => {
    return class DailyRotateFile {};
});

// Require the module under test AFTER mocks are set up
const AttackChainService = require('../services/attackChainService');
const ExploitService = require('../services/exploitService');
const ShellService = require('../services/shellService');
const fs = require('fs');

describe('AttackChainService - Auxiliary Module Filtering', () => {
    let mockDb;

    beforeEach(() => {
        jest.clearAllMocks();
        mockDb = {
            prepare: jest.fn().mockReturnValue({
                run: jest.fn().mockReturnValue({ lastInsertRowid: 1 }),
                get: jest.fn(),
                all: jest.fn().mockReturnValue([])
            })
        };
        // Reset the mock implementation for getDatabase
        require('../config/database').getDatabase.mockReturnValue(mockDb);

        // Mock ShellService
        ShellService.startListener.mockReturnValue('mock-session-id');
        ShellService.isConnected.mockReturnValue(true);
        ShellService.killSession.mockImplementation(() => {});

        // Mock create to return an ID
        AttackChainService.create = jest.fn().mockReturnValue(100);

        // Mock fs.mkdtempSync
        fs.mkdtempSync.mockReturnValue('/tmp/exploit-test');
        fs.existsSync.mockReturnValue(true);
        fs.writeFileSync.mockClear();
    });

    test('autoAttack should filter out auxiliary and post modules', async () => {
        const scanId = 1;
        const targetIp = '192.168.1.10';
        const userId = 1;

        // Mock matched exploits
        const mockExploits = [
            {
                exploit_id: 1,
                exploit_title: 'Valid Exploit',
                exploit_db_id: 'exploits/windows/smb/ms17_010_eternalblue',
                exploit_code: 'code',
                match_confidence: 100,
                port: 445
            },
            {
                exploit_id: 2,
                exploit_title: 'Auxiliary Fuzzer',
                exploit_db_id: 'auxiliary/fuzzers/ftp/ftp_pre_post',
                exploit_code: 'code',
                match_confidence: 100,
                port: 21
            },
            {
                exploit_id: 3,
                exploit_title: 'Post Module',
                exploit_db_id: 'post/windows/gather/credentials',
                exploit_code: 'code',
                match_confidence: 100,
                port: 445
            }
        ];

        ExploitService.getMatchedExploitsForTarget.mockReturnValue(mockExploits);

        ExploitService.getAttackableSummary.mockReturnValue([
            { service: 'smb', port: 445, hasExploits: true },
            { service: 'ftp', port: 21, hasExploits: true }
        ]);

        // Mock executeChain to return immediately
        AttackChainService.executeChain = jest.fn().mockResolvedValue({
            executionId: 1,
            status: 'running',
            totalSteps: 5
        });

        await AttackChainService.autoAttack(scanId, targetIp, userId);

        // Verify that create was called with filtered steps
        const createCall = AttackChainService.create.mock.calls[0][0];
        const steps = createCall.steps;

        const exploitSteps = steps.filter(s => s.type === 'exploit');

        // Should only have 1 exploit (the valid one)
        expect(exploitSteps.length).toBe(1);
        expect(exploitSteps[0].exploitId).toBe(1);
        expect(exploitSteps[0].name).toContain('Valid Exploit');
    });

    test('_executeStep should NOT set LHOST/LPORT for auxiliary modules', async () => {
        const step = {
            type: 'exploit',
            name: 'Manual Auxiliary Run',
            exploitId: 2, // Auxiliary from previous test
            targetPort: 21
        };
        const scanId = 1;
        const targetIp = '192.168.1.10';
        const chain = { strategy: 'aggressive' };
        const params = { LHOST: '10.0.0.1', LPORT: '4444' };

        // Mock DB prepare to return the auxiliary exploit
        const mockExploit = {
            id: 2,
            title: 'Auxiliary Fuzzer',
            exploit_db_id: 'auxiliary/fuzzers/ftp/ftp_pre_post',
            platform: 'linux',
            source: 'metasploit',
            port: 21,
            match_confidence: 100
        };

        mockDb.prepare.mockReturnValue({
            get: jest.fn().mockReturnValue(mockExploit),
            all: jest.fn().mockReturnValue([mockExploit]),
            run: jest.fn()
        });

        // Mock ExploitDbSyncService
        const ExploitDbSyncService = require('../services/exploitDbSyncService');
        ExploitDbSyncService.getExploitCode.mockReturnValue({
            language: 'ruby',
            code: 'require "msf/core"\nclass MetasploitModule < Msf::Auxiliary\nend'
        });

        await AttackChainService._executeStep(step, scanId, targetIp, 21, chain, params);

        // Find the call that writes exploit.rc
        const writeCalls = fs.writeFileSync.mock.calls;
        const rcWrite = writeCalls.find(call => call[0].endsWith('exploit.rc'));

        expect(rcWrite).toBeDefined();
        const rcContent = rcWrite[1];

        expect(rcContent).toContain('use auxiliary/fuzzers/ftp/ftp_pre_post');
        expect(rcContent).not.toContain('set LHOST 10.0.0.1');
        expect(rcContent).not.toContain('set LPORT 4444');
    });

    test('_executeStep SHOULD set LHOST/LPORT for standard exploits', async () => {
        const step = {
            type: 'exploit',
            name: 'Standard Exploit',
            exploitId: 1,
            targetPort: 445
        };
        const scanId = 1;
        const targetIp = '192.168.1.10';
        const chain = { strategy: 'aggressive' };
        const params = { LHOST: '10.0.0.1', LPORT: '4444' };

        // Mock DB prepare to return the standard exploit
        const mockExploit = {
            id: 1,
            title: 'Standard Exploit',
            exploit_db_id: 'exploits/windows/smb/ms17_010_eternalblue',
            platform: 'windows',
            source: 'metasploit',
            port: 445,
            match_confidence: 100
        };

        mockDb.prepare.mockReturnValue({
            get: jest.fn().mockReturnValue(mockExploit),
            all: jest.fn().mockReturnValue([mockExploit]),
            run: jest.fn()
        });

        // Mock ExploitDbSyncService
        const ExploitDbSyncService = require('../services/exploitDbSyncService');
        ExploitDbSyncService.getExploitCode.mockReturnValue({
            language: 'ruby',
            code: 'require "msf/core"\nclass MetasploitModule < Msf::Exploit\nend'
        });

        fs.writeFileSync.mockClear();

        await AttackChainService._executeStep(step, scanId, targetIp, 445, chain, params);

        // Find the call that writes exploit.rc
        const writeCalls = fs.writeFileSync.mock.calls;
        const rcWrite = writeCalls.find(call => call[0].endsWith('exploit.rc'));

        expect(rcWrite).toBeDefined();
        const rcContent = rcWrite[1];

        expect(rcContent).toContain('use exploits/windows/smb/ms17_010_eternalblue');
        expect(rcContent).toContain('set LHOST 10.0.0.1');
        expect(rcContent).toContain('set LPORT 4444');
    });
});
