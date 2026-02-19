const { doubleCsrf } = require("csrf-csrf");
const logger = require('../services/logger');
const { CSRF_SECRET, isCookieSecure } = require('../config/security');

const {
    doubleCsrfProtection,
    generateCsrfToken: generateTokenInternal
} = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    cookieName: "x-csrf-token",
    cookieOptions: {
        httpOnly: true,
        sameSite: "strict",
        secure: isCookieSecure,
        path: "/"
    },
    size: 64,
    ignoredMethods: ["GET", "HEAD", "OPTIONS"],
    getTokenFromRequest: (req) => req.headers["x-csrf-token"] || req.body._csrf,
    getSessionIdentifier: (req) => req.session.id // Bind token to session
});

// Authentication middleware - checks if user is logged in
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        // Check if password change is required
        if (req.session.forcePasswordChange && 
            req.originalUrl !== '/api/auth/change-password' && 
            req.originalUrl !== '/api/auth/logout' &&
            req.originalUrl !== '/api/auth/status') {
            return res.status(403).json({
                error: 'Passwortänderung erforderlich',
                forcePasswordChange: true
            });
        }
        return next();
    }
    logger.warn(`Unauthorized access attempt to ${req.path} from ${req.ip}`);
    return res.status(401).json({ error: 'Nicht authentifiziert. Bitte einloggen.' });
}

// Session timeout middleware (30 minutes)
function sessionTimeout(req, res, next) {
    const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes in ms

    if (req.session && req.session.userId) {
        const now = Date.now();
        const lastActivity = req.session.lastActivity || now;

        if (now - lastActivity > SESSION_TIMEOUT) {
            logger.info(`Session timeout for user ${req.session.username} (ID: ${req.session.userId})`);
            req.session.destroy((err) => {
                if (err) {
                    logger.error('Error destroying timed-out session:', err);
                }
            });
            return res.status(401).json({ 
                error: 'Sitzung abgelaufen. Bitte erneut einloggen.',
                sessionExpired: true 
            });
        }

        // Update last activity timestamp
        req.session.lastActivity = now;
    }
    next();
}

// Wrapper for doubleCsrfProtection to handle errors uniformly
const csrfProtection = (req, res, next) => {
    // Skip CSRF for tests if needed, or mock it.
    // However, tests might want to test CSRF too.
    // The current tests expect CSRF token to be returned and used.
    
    // For tests, allow bypassing if needed, but here we want to test it.
    // However, integration tests might fail if they don't handle cookies correctly.
    // The current tests seem to handle cookies via supertest agent.

    // We can conditionally skip if NODE_ENV is test AND we want to skip it?
    // But the tests seem to expect csrf protection to be active (they set X-CSRF-Token).

    doubleCsrfProtection(req, res, (err) => {
        if (err && err.code === 'EBADCSRFTOKEN') {
            logger.warn(`CSRF token mismatch for ${req.path} from ${req.ip}`);
            return res.status(403).json({ error: 'Ungültiges CSRF-Token' });
        } else if (err) {
            logger.error('CSRF error:', err);
            return res.status(403).json({ error: 'CSRF Fehler' });
        }
        next();
    });
};

// Generate CSRF token
function generateCsrfToken(req, res) {
    return generateTokenInternal(req, res);
}

module.exports = {
    requireAuth,
    sessionTimeout,
    csrfProtection,
    generateCsrfToken
};
