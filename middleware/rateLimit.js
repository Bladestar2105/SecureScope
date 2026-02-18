const rateLimit = require('express-rate-limit');
const logger = require('../services/logger');

// Rate limiter for login attempts: max 5 attempts in 15 minutes
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: {
        error: 'Zu viele Login-Versuche. Bitte versuchen Sie es in 15 Minuten erneut.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for login from IP: ${req.ip}`);
        logger.audit('LOGIN_RATE_LIMITED', { ip: req.ip, username: req.body.username });
        res.status(options.statusCode).json(options.message);
    },
    keyGenerator: (req) => {
        return req.ip;
    }
});

// Rate limiter for scan requests: max 10 scans per 5 minutes
const scanLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10,
    message: {
        error: 'Zu viele Scan-Anfragen. Bitte warten Sie einige Minuten.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for scans from IP: ${req.ip}, User: ${req.session?.username}`);
        logger.audit('SCAN_RATE_LIMITED', { 
            ip: req.ip, 
            userId: req.session?.userId,
            username: req.session?.username 
        });
        res.status(options.statusCode).json(options.message);
    },
    keyGenerator: (req) => {
        // Rate limit per user session if available, otherwise by IP
        return req.session?.userId ? `user_${req.session.userId}` : req.ip;
    }
});

// General API rate limiter: max 100 requests per minute
const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    message: {
        error: 'Zu viele Anfragen. Bitte versuchen Sie es später erneut.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

module.exports = {
    loginLimiter,
    scanLimiter,
    apiLimiter
};