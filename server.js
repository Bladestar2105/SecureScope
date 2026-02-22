require('dotenv').config();
const { initializeDatabase, closeDatabase } = require('./config/database');
const schedulerService = require('./services/schedulerService');
const scannerService = require('./services/scanner');
const logger = require('./services/logger');
const websocketService = require('./services/websocketService');
const app = require('./app');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3000;

function startServer() {
    try {
        initializeDatabase();
        logger.info('Database initialized');

        // Initialize scanner service (reset zombie scans)
        scannerService.initialize();
        logger.info('Scanner service initialized');

        // Initialize scheduler for cron jobs
        schedulerService.initialize();
        logger.info('Scheduler initialized');

        // Check and auto-initialize Metasploit if missing or incomplete
        const msfDir = path.join(__dirname, 'data', 'metasploit');
        const msfConsole = path.join(msfDir, 'msfconsole');
        const msfGitDir = path.join(msfDir, '.git');
        const msfNeedsInit = !fs.existsSync(msfDir) || !fs.existsSync(msfGitDir) || !fs.existsSync(msfConsole);

        if (msfNeedsInit) {
            logger.info('Metasploit framework not found or incomplete. Initializing background download...');
            const workerScript = path.join(__dirname, 'services', 'syncWorker.js');
            const worker = spawn('node', ['--max-old-space-size=1024', workerScript, 'metasploit', '1'], {
                cwd: __dirname,
                env: { ...process.env, DATABASE_PATH: process.env.DATABASE_PATH || path.join(__dirname, 'database', 'securescope.db') },
                stdio: ['ignore', 'pipe', 'pipe']
            });

            // Log worker output so progress is visible
            let workerBuffer = '';
            worker.stdout.on('data', (data) => {
                workerBuffer += data.toString();
                const lines = workerBuffer.split('\n');
                workerBuffer = lines.pop();
                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const msg = JSON.parse(line);
                        if (msg.phase === 'error') {
                            logger.error('Metasploit background sync error: ' + msg.message);
                        } else if (msg.phase === 'done') {
                            logger.info('Metasploit background sync completed: ' + msg.message);
                        } else {
                            logger.info('Metasploit sync: [' + msg.percent + '%] ' + msg.message);
                        }
                    } catch (e) {
                        logger.debug('Metasploit worker output: ' + line);
                    }
                }
            });

            worker.stderr.on('data', (data) => {
                const errMsg = data.toString().trim();
                if (errMsg) logger.warn('Metasploit worker stderr: ' + errMsg);
            });

            worker.on('close', (code) => {
                if (code === 0) {
                    logger.info('Metasploit background download completed successfully.');
                } else {
                    logger.error('Metasploit background download failed with exit code ' + code);
                }
            });

            worker.on('error', (err) => {
                logger.error('Metasploit background worker spawn error: ' + err.message);
            });

            worker.unref();
            logger.info('Metasploit download started in background.');
        }

        const server = app.listen(PORT, () => {
            logger.info(`SecureScope Server läuft auf Port ${PORT}`);
            logger.info(`Umgebung: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`Öffne http://localhost:${PORT} im Browser`);
        });

        // Initialize WebSocket Service
        websocketService.initialize(server);

        // Graceful shutdown
        const shutdown = (signal) => {
            logger.info(`${signal} empfangen. Server wird heruntergefahren...`);
            schedulerService.shutdown();
            server.close(() => {
                closeDatabase();
                logger.info('Server erfolgreich beendet');
                process.exit(0);
            });

            // Force shutdown after 10 seconds
            setTimeout(() => {
                logger.error('Erzwungenes Herunterfahren nach Timeout');
                process.exit(1);
            }, 10000);
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));

        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', err);
            shutdown('uncaughtException');
        });

        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
        });

        return server;
    } catch (err) {
        logger.error('Failed to start server:', err);
        process.exit(1);
    }
}

// Start the server if this is the main module
if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };
