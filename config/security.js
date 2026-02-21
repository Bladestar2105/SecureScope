const crypto = require('crypto');

/**
 * Security configuration and secret management.
 * Centralizes the loading and validation of security-related secrets.
 */

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Helper to get a secret from environment variables or generate a secure random one.
 * @param {string} envVar The environment variable name
 * @returns {string} The secret
 */
function getSecret(envVar) {
    const value = process.env[envVar];
    const insecureFallbacks = [
        'fallback-secret-change-me',
        'securescope-credential-key-change-me',
        'change_this_to_a_random_secret_in_production',
        'change_this_csrf_secret_in_production',
        'your_random_session_secret_here',
        'your_random_csrf_secret_here',
        'test-secret-key'
    ];

    const isInsecure = (val) => {
        if (!val) return true;
        if (val.length < 32) return true;
        const lowerVal = val.toLowerCase();
        if (insecureFallbacks.includes(val)) return true;
        if (lowerVal.includes('change-me') || lowerVal.includes('change_me')) return true;
        if (lowerVal.includes('fallback')) return true;
        if (lowerVal.includes('secret') && lowerVal.length < 40) return true; // generic 'secret' in string
        return false;
    };

    if (value && !isInsecure(value)) {
        return value;
    }

    // If we reach here, the value is missing or insecure.
    // We ALWAYS generate a random secret to ensure security.

    if (isProduction) {
        if (value) {
            console.error(`[CRITICAL SECURITY WARNING] Insecure ${envVar} provided in production environment! Ignoring it and using a generated secret. Sessions and encrypted data may not persist.`);
        } else {
            console.error(`[CRITICAL SECURITY WARNING] Required environment variable ${envVar} is missing in production! Using a generated secret. Sessions and encrypted data may not persist.`);
        }
    } else {
        if (value) {
            console.warn(`[SECURITY WARNING] Insecure ${envVar} detected in development. Ignoring it and using a generated secret for security.`);
        } else {
            console.info(`[SECURITY INFO] ${envVar} is not set. Using a temporary random secret.`);
        }
    }

    // Generate random secret (32 bytes = 64 hex characters)
    return crypto.randomBytes(32).toString('hex');
}

const SESSION_SECRET = getSecret('SESSION_SECRET');
const CSRF_SECRET = getSecret('CSRF_SECRET');
const CREDENTIAL_SECRET = getSecret('CREDENTIAL_SECRET');

const isCookieSecure = process.env.COOKIE_SECURE !== undefined
    ? process.env.COOKIE_SECURE === 'true'
    : isProduction;

module.exports = {
    SESSION_SECRET,
    CSRF_SECRET,
    CREDENTIAL_SECRET,
    isProduction,
    isCookieSecure
};
