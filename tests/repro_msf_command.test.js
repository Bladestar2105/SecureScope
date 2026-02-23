const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');

// Mocks
jest.mock('fs');
jest.mock('child_process');
// Use factory to avoid loading real module dependencies
jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));
jest.mock('../services/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    audit: jest.fn()
}));
jest.mock('../services/shellService', () => ({
    startListener: jest.fn(),
    isConnected: jest.fn(),
    killSession: jest.fn()
}));
jest.mock('../services/exploitDbSyncService', () => ({
    getExploitCode: jest.fn()
}));

// Setup mocks before requiring service
// const { getDatabase } = require('../config/database'); // Moved inside beforeEach
// const ExploitDbSyncService = require('../services/exploitDbSyncService');
// const ShellService = require('../services/shellService');

describe('AttackChainService MSF Command Generation', () => {
    jest.setTimeout(10000);
    let AttackChainService;
    let getDatabase;
    let ExploitDbSyncService;
    let ShellService;
    let execMock, execSyncMock;

    beforeEach(() => {
        jest.resetModules();
        jest.clearAllMocks();

        // Re-require mocks to ensure we configure the instance used by the service
        const dbModule = require('../config/database');
        getDatabase = dbModule.getDatabase;
        ExploitDbSyncService = require('../services/exploitDbSyncService');
        ShellService = require('../services/shellService');
        const cp = require('child_process');
        execMock = cp.exec;
        execSyncMock = cp.execSync;

        // Database Mock
        getDatabase.mockReturnValue({
            prepare: jest.fn().mockReturnValue({
                get: jest.fn(),
                all: jest.fn(),
                run: jest.fn()
            })
        });

        const fs = require('fs');
        // Mock fs.existsSync to simulate Metasploit presence
        fs.existsSync.mockImplementation((p) => {
            if (p.includes('metasploit/msfconsole')) return true;
            if (p.includes('metasploit/Gemfile')) return true;
            if (p.includes('metasploit/vendor/bundle')) return true;
            return false;
        });

        fs.mkdtempSync.mockReturnValue('/tmp/test-exploit');
        fs.writeFileSync.mockImplementation(() => {});
        fs.rmSync.mockImplementation(() => {});

        // Mock Exploit Code
        ExploitDbSyncService.getExploitCode.mockReturnValue({
            code: 'require "msf/core"; class Metasploit3 < Msf::Exploit::Remote; end',
            language: 'ruby'
        });

        // Mock ShellService
        ShellService.startListener.mockReturnValue('session-123');
        ShellService.isConnected.mockReturnValue(false);
        ShellService.killSession.mockImplementation(() => {});

        // Mock exec to capture command
        execMock.mockImplementation((cmd, opts, cb) => {
            if (cb) cb(null, 'stdout', 'stderr');
        });

        execSyncMock.mockImplementation((cmd) => {
            return 'ok';
        });

        // Require Service
        AttackChainService = require('../services/attackChainService');
    });

    test('generates correct msfconsole command with bundle configuration', async () => {
        const step = {
            type: 'exploit',
            name: 'Test Exploit',
            exploitId: 130555
        };

        const exploitMock = {
            id: 130555,
            title: 'Test MSF Exploit',
            source: 'metasploit',
            exploit_db_id: 'exploits/windows/smb/ms08_067_netapi',
            platform: 'windows',
            port: 445
        };

        // Mock DB query for exploit
        const db = getDatabase();
        // db.prepare() returns the stmt object.
        // We need to make sure the get() method on that object returns our exploit.
        const stmt = db.prepare();
        stmt.get.mockReturnValue(exploitMock);

        // Also ensure prepare returns this statement
        db.prepare.mockReturnValue(stmt);

        await AttackChainService._executeStep(step, 101, '192.168.1.1', 445, {}, { LHOST: '10.0.0.1', LPORT: 4444 });

        // Verify exec was called
        const logger = require('../services/logger');
        if (logger.error.mock.calls.length > 0) {
            console.log('Logger Error Calls:', logger.error.mock.calls);
        }
        if (logger.warn.mock.calls.length > 0) {
            console.log('Logger Warn Calls:', logger.warn.mock.calls);
        }

        expect(execMock).toHaveBeenCalled();
        const cmd = execMock.mock.calls[0][0];

        // Assertions for the fixed behavior
        expect(cmd).toContain('BUNDLE_GEMFILE=');
        expect(cmd).toContain('bundle exec ./msfconsole');
    });
});
