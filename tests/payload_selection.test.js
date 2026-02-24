const fs = require('fs');
const path = require('path');
const cp = require('child_process');

// Mocks
jest.mock('fs');
jest.mock('child_process');
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
    getFreePort: jest.fn(),
    killSession: jest.fn()
}));
jest.mock('../services/exploitDbSyncService', () => ({
    getExploitCode: jest.fn()
}));

const AttackChainService = require('../services/attackChainService');
const { getDatabase } = require('../config/database');
const ExploitDbSyncService = require('../services/exploitDbSyncService');
const ShellService = require('../services/shellService');

describe('AttackChainService Payload Selection', () => {
    let writtenFiles = {};

    beforeEach(() => {
        jest.clearAllMocks();
        writtenFiles = {};

        // Database Mock
        getDatabase.mockReturnValue({
            prepare: jest.fn().mockReturnValue({
                get: jest.fn(),
                all: jest.fn(),
                run: jest.fn()
            })
        });

        // FS Mock
        fs.existsSync.mockReturnValue(true);
        fs.mkdtempSync.mockReturnValue('/tmp/test-exploit');
        fs.writeFileSync.mockImplementation((file, content) => {
            writtenFiles[path.basename(file)] = content;
        });
        fs.rmSync.mockImplementation(() => {});
        fs.mkdirSync.mockImplementation(() => {});

        // ShellService Mock
        ShellService.getFreePort.mockResolvedValue(4444);
        ShellService.startListener.mockReturnValue('session-1');
        // Return true immediately to avoid 5 second wait loop
        ShellService.isConnected.mockReturnValue(true);

        // Child Process Mock (exec)
        cp.exec.mockImplementation((cmd, opts, cb) => {
            if (typeof opts === 'function') {
                cb = opts;
                opts = {};
            }
            // Execute callback immediately
            if (cb) cb(null, 'stdout', 'stderr');
            return { stdout: { on: jest.fn() }, stderr: { on: jest.fn() } };
        });
        // Also mock execPromise if used (util.promisify(exec))?
        // _executeStep uses exec directly for exploit execution, but execPromise for compilation.
        // But since we use Metasploit exploits in tests (source='metasploit'), compilation is skipped.
        // Wait, compilation is skipped if language is ruby and source is metasploit.
        // In my tests, I set source='metasploit'.

        // Exploit Code Mock
        ExploitDbSyncService.getExploitCode.mockReturnValue({
            code: 'require "msf/core"; class Metasploit3 < Msf::Exploit::Remote; end',
            language: 'ruby'
        });
    });

    async function testPayloadSelection(exploitOverride, expectedPayload) {
        const step = {
            type: 'exploit',
            name: 'Test Exploit',
            exploitId: 1
        };

        const exploit = {
            id: 1,
            title: 'Test Exploit',
            source: 'metasploit',
            exploit_db_id: 'exploits/test/exploit',
            platform: 'multi',
            port: 80,
            match_confidence: 100,
            ...exploitOverride
        };

        const db = getDatabase();
        const stmt = db.prepare();
        stmt.get.mockReturnValue(exploit); // For step.exploitId query
        db.prepare.mockReturnValue(stmt);

        await AttackChainService._executeStep(step, 101, '192.168.1.1', 80, {}, { LHOST: '10.0.0.1', LPORT: 4444 });

        const rcContent = writtenFiles['exploit.rc'];

        if (!rcContent) {
            console.error('No exploit.rc written! Written files:', Object.keys(writtenFiles));
        }

        expect(rcContent).toBeDefined();
        // Check if payload is set correctly.
        expect(rcContent).toMatch(new RegExp(`set PAYLOAD ${expectedPayload}`, 'i'));
    }

    test('selects windows/shell_reverse_tcp for Windows platform', async () => {
        await testPayloadSelection({
            platform: 'Windows',
            exploit_db_id: 'exploits/windows/smb/ms17_010_eternalblue'
        }, 'windows/shell_reverse_tcp');
    });

    test('selects windows/shell_reverse_tcp for "win" platform', async () => {
        await testPayloadSelection({
            platform: 'win', // Metasploit often uses 'win'
            exploit_db_id: 'exploits/windows/http/apache_modjk_overflow'
        }, 'windows/shell_reverse_tcp');
    });

    test('selects cmd/windows/reverse_powershell for Windows CMD', async () => {
        await testPayloadSelection({
            platform: 'Windows_cmd',
            exploit_db_id: 'exploits/windows/local/bypassuac'
        }, 'cmd/windows/reverse_powershell');
    });

    test('selects bsd/x86/shell_reverse_tcp for BSD binary', async () => {
        await testPayloadSelection({
            platform: 'Bsd',
            exploit_db_id: 'exploits/freebsd/ftp/proftp_telnet_iac'
        }, 'bsd/x86/shell_reverse_tcp');
    });

    test('selects cmd/unix/reverse for Linux CMD', async () => {
        await testPayloadSelection({
            platform: 'Linux_cmd',
            exploit_db_id: 'exploits/linux/http/rce'
        }, 'cmd/unix/reverse');
    });

    test('selects linux/x86/shell_reverse_tcp for Linux binary', async () => {
        await testPayloadSelection({
            platform: 'Linux',
            exploit_db_id: 'exploits/linux/local/sudo_baron_samedit'
        }, 'linux/x86/shell_reverse_tcp');
    });

    test('selects php/reverse_php for PHP', async () => {
        await testPayloadSelection({
            platform: 'Php',
            exploit_db_id: 'exploits/multi/http/php_cgi_arg_injection'
        }, 'php/reverse_php');
    });

    test('guesses Windows from path when platform is generic', async () => {
        await testPayloadSelection({
            platform: 'Cgi', // Generic
            exploit_db_id: 'exploits/windows/http/bad_cgi'
        }, 'windows/shell_reverse_tcp');
    });
});
