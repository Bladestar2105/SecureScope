const crypto = require('crypto');
const logger = require('../services/logger');

/**
 * Validates and retrieves security secrets.
 * In production, missing secrets will throw an error.
 * In other environments, missing secrets will be replaced with a random value.
 */

const CSRF_SECRET = process.env.CSRF_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PROD = process.env.NODE_ENV === 'production';
const FALLBACK_VALUE = 'fallback-secret-change-me';

if (IS_PROD) {
    if (!CSRF_SECRET || CSRF_SECRET === FALLBACK_VALUE) {
        logger.error('CRITICAL: CSRF_SECRET is not set or using insecure fallback in production!');
        throw new Error('CSRF_SECRET environment variable is required in production');
    }
    if (!SESSION_SECRET || SESSION_SECRET === FALLBACK_VALUE) {
        logger.error('CRITICAL: SESSION_SECRET is not set or using insecure fallback in production!');
        throw new Error('SESSION_SECRET environment variable is required in production');
    }
}

// Generate random secrets if not provided (non-production)
const effectiveCsrfSecret = CSRF_SECRET && CSRF_SECRET !== FALLBACK_VALUE
    ? CSRF_SECRET
    : crypto.randomBytes(64).toString('hex');

const effectiveSessionSecret = SESSION_SECRET && SESSION_SECRET !== FALLBACK_VALUE
    ? SESSION_SECRET
    : crypto.randomBytes(64).toString('hex');

if ((!CSRF_SECRET || CSRF_SECRET === FALLBACK_VALUE) && process.env.NODE_ENV !== 'test') {
    logger.warn('CSRF_SECRET not provided or insecure fallback used. Generated a random secret for this session.');
}

if ((!SESSION_SECRET || SESSION_SECRET === FALLBACK_VALUE) && process.env.NODE_ENV !== 'test') {
    logger.warn('SESSION_SECRET not provided or insecure fallback used. Generated a random secret for this session.');
}

module.exports = {
    getCsrfSecret: () => effectiveCsrfSecret,
    getSessionSecret: () => effectiveSessionSecret
};
