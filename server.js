require('dotenv').config();
const { initializeDatabase, closeDatabase } = require('./config/database');
const schedulerService = require('./services/schedulerService');
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

        // Initialize scheduler for cron jobs
        schedulerService.initialize();
        logger.info('Scheduler initialized');

        // Check and auto-initialize Metasploit if missing
        const msfDir = path.join(__dirname, 'data', 'metasploit');
        if (!fs.existsSync(msfDir)) {
            logger.info('Metasploit framework not found. Initializing background download...');
            const workerScript = path.join(__dirname, 'services', 'syncWorker.js');
            const worker = spawn('node', [workerScript, 'metasploit', '1'], {
                detached: true,
                stdio: 'ignore'
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
