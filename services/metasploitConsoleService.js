const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const EventEmitter = require('events');
const logger = require('./logger');
const websocketService = require('./websocketService');

class MetasploitConsoleService extends EventEmitter {
    constructor() {
        super();
        this.sessions = new Map(); // sessionId -> { process, ws, createdBy, createdAt, command }
        websocketService.registerHandler(/^\/api\/metasploit\/([a-f0-9-]+)$/, (ws, req, match) => {
            this.handleWebSocket(ws, match[1]);
        });
    }

    _buildLaunchConfig() {
        const msfRoot = path.join(__dirname, '..', 'data', 'metasploit');
        const localMsfConsole = path.join(msfRoot, 'msfconsole');
        const gemfilePath = path.join(msfRoot, 'Gemfile');
        const bundlePath = path.join(msfRoot, 'vendor', 'bundle');

        if (fs.existsSync(localMsfConsole) && fs.existsSync(gemfilePath)) {
            const env = {
                ...process.env,
                BUNDLE_GEMFILE: gemfilePath,
                RAILS_ENV: 'production',
                BUNDLE_DISABLE_SHARED_GEMS: '1'
            };
            if (fs.existsSync(bundlePath)) {
                env.BUNDLE_PATH = bundlePath;
            }

            return {
                shell: 'bash',
                args: ['-lc', 'cd "' + msfRoot + '" && bundle exec ./msfconsole -q'],
                env,
                commandLabel: 'bundle exec ./msfconsole -q'
            };
        }

        return {
            shell: 'bash',
            args: ['-lc', 'msfconsole -q'],
            env: { ...process.env },
            commandLabel: 'msfconsole -q'
        };
    }

    startSession(userId, options = {}) {
        const sessionId = uuidv4();
        const launch = this._buildLaunchConfig();

        const proc = spawn(launch.shell, launch.args, {
            env: launch.env,
            stdio: ['pipe', 'pipe', 'pipe']
        });

        const session = {
            id: sessionId,
            process: proc,
            ws: null,
            createdBy: userId,
            createdAt: new Date(),
            command: launch.commandLabel
        };

        this.sessions.set(sessionId, session);

        proc.on('error', (err) => {
            logger.error(`Metasploit console error for session ${sessionId}:`, err);
            if (session.ws && session.ws.readyState === 1) {
                session.ws.send(`\r\n[error] ${err.message}\r\n`);
            }
            this.stopSession(sessionId);
        });

        proc.on('close', (code, signal) => {
            logger.info(`Metasploit session ${sessionId} closed (code=${code}, signal=${signal || 'none'})`);
            if (session.ws && session.ws.readyState === 1) {
                session.ws.send(`\r\n[metasploit closed] code=${code ?? 'null'} signal=${signal || 'none'}\r\n`);
                session.ws.close();
            }
            this.sessions.delete(sessionId);
        });

        const streamHandler = (data) => {
            if (session.ws && session.ws.readyState === 1) {
                session.ws.send(data.toString('utf8'));
            }
        };
        proc.stdout.on('data', streamHandler);
        proc.stderr.on('data', streamHandler);

        // Optional bootstrap commands (e.g. started from "Angriff starten")
        if (Array.isArray(options.bootstrapCommands) && options.bootstrapCommands.length > 0) {
            const safeCommands = options.bootstrapCommands
                .map(c => String(c || '').replace(/[\r\n]/g, '').trim())
                .filter(Boolean)
                .slice(0, 40);

            if (safeCommands.length > 0) {
                setTimeout(() => {
                    try {
                        for (const cmd of safeCommands) {
                            proc.stdin.write(cmd + '\n');
                        }
                    } catch (e) {
                        logger.warn(`Failed to write bootstrap commands for session ${sessionId}:`, e);
                    }
                }, 1200);
            }
        }

        return { sessionId, command: launch.commandLabel };
    }

    handleWebSocket(ws, sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            ws.close(1008, 'Session not found');
            return;
        }

        session.ws = ws;
        ws.send('\r\n[connected] Metasploit console ready.\r\n');

        ws.on('message', (message) => {
            try {
                if (session.process && !session.process.killed) {
                    session.process.stdin.write(message);
                }
            } catch (err) {
                logger.error(`Failed to write to Metasploit session ${sessionId}:`, err);
            }
        });

        ws.on('close', () => {
            session.ws = null;
        });
    }

    stopSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;

        try {
            if (session.process && !session.process.killed) {
                session.process.kill('SIGTERM');
            }
        } catch (e) {
            logger.warn(`Failed to stop Metasploit session ${sessionId}:`, e);
        }

        this.sessions.delete(sessionId);
        return true;
    }

    getSession(sessionId) {
        return this.sessions.get(sessionId) || null;
    }
}

module.exports = new MetasploitConsoleService();
