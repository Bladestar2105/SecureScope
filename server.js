require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const { initializeDatabase, closeDatabase } = require('./config/database');
const { sessionTimeout, csrfProtection } = require('./middleware/auth');
const { apiLimiter } = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scan');
const logger = require('./services/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Security headers with helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? false : true,
    credentials: true
}));

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Session configuration
app.use(session({
    name: 'securescope.sid',
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// Session timeout middleware
app.use(sessionTimeout);

// General API rate limiting
app.use('/api/', apiLimiter);

// CSRF protection for API routes (except login)
app.use('/api/', csrfProtection);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve dashboard
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpunkt nicht gefunden' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: 'Interner Serverfehler' });
});

// Initialize database and start server
function startServer() {
    try {
        initializeDatabase();
        logger.info('Database initialized');

        const server = app.listen(PORT, () => {
            logger.info(`SecureScope Server läuft auf Port ${PORT}`);
            logger.info(`Umgebung: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`Öffne http://localhost:${PORT} im Browser`);
        });

        // Graceful shutdown
        const shutdown = (signal) => {
            logger.info(`${signal} empfangen. Server wird heruntergefahren...`);
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