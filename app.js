require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const { sessionTimeout, csrfProtection } = require('./middleware/auth');
const { apiLimiter } = require('./middleware/rateLimit');
const { SESSION_SECRET, isCookieSecure } = require('./config/security');
const logger = require('./services/logger');

// Route imports
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scan');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const userRoutes = require('./routes/users');
const scheduleRoutes = require('./routes/schedules');
const notificationRoutes = require('./routes/notifications');
const fingerprintRoutes = require('./routes/fingerprints');
const exploitRoutes = require('./routes/exploits');
const attackChainRoutes = require('./routes/attackChains');
const auditRoutes = require('./routes/audits');
const credentialRoutes = require('./routes/credentials');
const dbUpdateRoutes = require('./routes/dbUpdate');
const ghdbRoutes = require('./routes/ghdb');

const app = express();

// Trust proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Security headers with helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? false : true,
    credentials: true
}));

// Compression for response optimization
app.use(compression());

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Cookie parser
app.use(cookieParser(SESSION_SECRET));

// Session configuration
app.use(session({
    name: 'securescope.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isCookieSecure,
        sameSite: process.env.NODE_ENV === 'test' ? 'lax' : 'strict',
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
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/users', userRoutes);
app.use('/api/schedules', scheduleRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/fingerprints', fingerprintRoutes);
app.use('/api/exploits', exploitRoutes);
app.use('/api/attack-chains', attackChainRoutes);
app.use('/api/audits', auditRoutes);
app.use('/api/credentials', credentialRoutes);
app.use('/api/db-update', dbUpdateRoutes);
app.use('/api/ghdb', ghdbRoutes);

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

module.exports = app;
