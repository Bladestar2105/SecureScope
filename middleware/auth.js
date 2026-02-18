const logger = require('../services/logger');

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

// CSRF token middleware
function csrfProtection(req, res, next) {
    // Skip CSRF for GET, HEAD, OPTIONS requests
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) {
        return next();
    }

    // Skip CSRF for login (no session yet)
    if (req.path === '/api/auth/login' || req.path === '/auth/login' || req.originalUrl === '/api/auth/login') {
        return next();
    }

    const token = req.headers['x-csrf-token'] || req.body._csrf;
    
    if (!token || token !== req.session.csrfToken) {
        logger.warn(`CSRF token mismatch for ${req.path} from ${req.ip}`);
        return res.status(403).json({ error: 'Ungültiges CSRF-Token' });
    }

    next();
}

// Generate CSRF token
function generateCsrfToken(req) {
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = token;
    return token;
}

module.exports = {
    requireAuth,
    sessionTimeout,
    csrfProtection,
    generateCsrfToken
};