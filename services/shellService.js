const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const logger = require('./logger');
const websocketService = require('./websocketService');

class ShellService extends EventEmitter {
    constructor() {
        super();
        this.sessions = new Map(); // sessionId -> { process, port, connected: boolean, createdAt: Date }

        // Register WebSocket handler
        websocketService.registerHandler(/^\/api\/shell\/([a-f0-9-]+)$/, (ws, req, match) => {
            this.handleWebSocket(ws, match[1]);
        });
    }

    /**
     * Starts a netcat listener on the specified port.
     * @param {number} port - The port to listen on.
     * @returns {string} - The session ID.
     */
    startListener(port) {
        const sessionId = uuidv4();
        // Use -l (listen), -v (verbose), -n (numeric only), -p (port)
        // Note: Check if netcat-openbsd or netcat-traditional usage.
        // Dockerfile installs netcat-openbsd.
        // Usage: nc -l -p 4444 -v -n
        const nc = spawn('nc', ['-l', '-v', '-n', '-p', port]);

        const session = {
            id: sessionId,
            process: nc,
            port: port,
            connected: false,
            createdAt: new Date(),
            buffer: [] // Buffer output until WS connects
        };

        this.sessions.set(sessionId, session);
        logger.info(`Started shell listener ${sessionId} on port ${port}`);

        // Handle output
        const handleOutput = (data, source) => {
            const text = data.toString();

            // Check for connection
            // netcat-openbsd verbose output on stderr: "Connection from 192.168.1.5 53214 received!" or similar
            if (!session.connected && (text.includes('Connection from') || text.includes('connect to'))) {
                session.connected = true;
                logger.info(`Shell session ${sessionId} connected!`);
                this.emit('connection', sessionId);
            }

            // Buffer or send to WS
            if (session.ws && session.ws.readyState === 1) { // OPEN
                session.ws.send(text);
            } else {
                session.buffer.push(text);
            }
        };

        nc.stdout.on('data', (data) => handleOutput(data, 'stdout'));
        nc.stderr.on('data', (data) => handleOutput(data, 'stderr'));

        nc.on('close', (code) => {
            logger.info(`Shell session ${sessionId} closed with code ${code}`);
            if (session.ws) {
                session.ws.close();
            }
            this.sessions.delete(sessionId);
            this.emit('close', sessionId);
        });

        nc.on('error', (err) => {
            logger.error(`Shell session ${sessionId} error:`, err);
            this.sessions.delete(sessionId);
        });

        return sessionId;
    }

    /**
     * Handles an incoming WebSocket connection for a shell session.
     */
    handleWebSocket(ws, sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            ws.close(1008, 'Session not found');
            return;
        }

        session.ws = ws;
        logger.info(`WebSocket attached to shell session ${sessionId}`);

        // Flush buffer
        if (session.buffer.length > 0) {
            for (const chunk of session.buffer) {
                ws.send(chunk);
            }
            session.buffer = [];
        }

        ws.on('message', (message) => {
            if (session.process && !session.process.killed) {
                try {
                    session.process.stdin.write(message);
                } catch (e) {
                    logger.error(`Error writing to shell ${sessionId}:`, e);
                }
            }
        });

        ws.on('close', () => {
            session.ws = null;
        });
    }

    /**
     * Kills a session.
     */
    killSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            if (session.process) session.process.kill();
            this.sessions.delete(sessionId);
        }
    }

    /**
     * Check if a session has an active connection (reverse shell established)
     */
    isConnected(sessionId) {
        const session = this.sessions.get(sessionId);
        return session && session.connected;
    }
}

module.exports = new ShellService();
