const net = require('net');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const logger = require('./logger');
const websocketService = require('./websocketService');

class ShellService extends EventEmitter {
    constructor() {
        super();
        this.sessions = new Map(); // sessionId -> { server, socket, port, connected: boolean, createdAt: Date, buffer: [] }

        // Register WebSocket handler
        websocketService.registerHandler(/^\/api\/shell\/([a-f0-9-]+)$/, (ws, req, match) => {
            this.handleWebSocket(ws, match[1]);
        });
    }

    /**
     * Starts a TCP listener on the specified port using Node.js net module.
     * @param {number} port - The port to listen on.
     * @returns {string} - The session ID.
     */
    startListener(port) {
        const sessionId = uuidv4();

        const session = {
            id: sessionId,
            server: null,
            socket: null,
            port: port,
            connected: false,
            createdAt: new Date(),
            buffer: [] // Buffer output until WS connects
        };

        const server = net.createServer((socket) => {
            logger.info(`Connection received on port ${port} for session ${sessionId}`);

            // Only accept one connection per listener (standard for reverse shells)
            if (session.socket) {
                logger.warn(`Rejected additional connection on port ${port}`);
                socket.end();
                return;
            }

            session.socket = socket;
            session.connected = true;
            this.emit('connection', sessionId);

            // Handle incoming data from the shell
            socket.on('data', (data) => {
                const text = data.toString('utf8'); // Convert buffer to string

                // Buffer or send to WS
                if (session.ws && session.ws.readyState === 1) { // OPEN
                    session.ws.send(text);
                } else {
                    session.buffer.push(text);
                }
            });

            socket.on('error', (err) => {
                logger.error(`Socket error on session ${sessionId}:`, err);
                this.killSession(sessionId);
            });

            socket.on('close', () => {
                logger.info(`Socket closed for session ${sessionId}`);
                session.socket = null;
                session.connected = false;
                // We keep the listener open? No, usually reverse shell is one-shot.
                // But let's keep it open in case of reconnection attempts or multiple stages?
                // For now, let's keep the listener active until explicitly killed by AttackChainService.
            });
        });

        server.on('error', (err) => {
            logger.error(`Listener error on port ${port}:`, err);
            this.sessions.delete(sessionId);
        });

        server.on('close', () => {
            logger.info(`Listener closed on port ${port}`);
            if (session.ws) {
                session.ws.close();
            }
            this.sessions.delete(sessionId);
            this.emit('close', sessionId);
        });

        try {
            server.listen(port, '0.0.0.0', () => {
                logger.info(`Started shell listener ${sessionId} on port ${port}`);
            });
            session.server = server;
            this.sessions.set(sessionId, session);
        } catch (err) {
            logger.error(`Failed to start listener on port ${port}:`, err);
            return null;
        }

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
            if (session.socket && !session.socket.destroyed) {
                try {
                    session.socket.write(message);
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
     * Kills a session (closes listener and socket).
     */
    killSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            if (session.socket) {
                session.socket.destroy();
            }
            if (session.server) {
                session.server.close();
            }
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

    /**
     * Finds a free port on the system by binding to port 0.
     * @returns {Promise<number>} - A free port number.
     */
    async getFreePort() {
        return new Promise((resolve, reject) => {
            const server = net.createServer();
            server.unref(); // Don't keep event loop active
            server.on('error', reject);
            server.listen(0, () => {
                const { port } = server.address();
                server.close(() => {
                    resolve(port);
                });
            });
        });
    }
}

module.exports = new ShellService();
