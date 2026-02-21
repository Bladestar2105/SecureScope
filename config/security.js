const crypto = require('crypto');

/**
 * Security configuration and secret management.
 * Centralizes the loading and validation of security-related secrets.
 */

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Helper to get a secret from environment variables or generate a fallback.
 * @param {string} envVar The environment variable name
 * @param {string|null} fallback Manual fallback (optional)
 * @returns {string} The secret
 */
function getSecret(envVar, fallback = null) {
    const value = process.env[envVar];
    const insecureFallbacks = [
        'fallback-secret-change-me',
        'securescope-credential-key-change-me',
        'securescope-salt-v1',
        'change_this_to_a_random_secret_in_production',
        'change_this_csrf_secret_in_production',
        'your_random_session_secret_here',
        'your_random_csrf_secret_here',
        'test-secret-key'
    ];

    const isInsecure = (val) => val && (insecureFallbacks.includes(val) || val.includes('change-me') || val.includes('fallback'));

    if (value && !isInsecure(value)) {
        return value;
    }

    if (isProduction) {
        if (value) {
            console.error(`[CRITICAL SECURITY WARNING] Insecure ${envVar} provided in production environment! Ignoring it and using a generated/fallback secret. Sessions and encrypted data may not persist.`);
        } else {
            console.error(`[CRITICAL SECURITY WARNING] Required environment variable ${envVar} is missing in production! Using a generated/fallback secret. Sessions and encrypted data may not persist.`);
        }

        if (fallback && !isInsecure(fallback)) {
            return fallback;
        }

        const randomSecret = crypto.randomBytes(64).toString('hex');
        return randomSecret;
    } else {
        // For non-production:
        if (value && isInsecure(value)) {
            // We allow insecure values in non-production but warn
            console.warn(`[SECURITY WARNING] Insecure ${envVar} detected. Using it anyway because NOT in production.`);
            return value;
        }
    }

    if (fallback) {
        return fallback;
    }

    // Generate random secret for non-production if none provided
    const randomSecret = crypto.randomBytes(32).toString('hex');
    console.warn(`[SECURITY NOTICE] ${envVar} is not set. Using a temporary random secret.`);
    return randomSecret;
}

const SESSION_SECRET = getSecret('SESSION_SECRET');
const CSRF_SECRET = getSecret('CSRF_SECRET');
const CREDENTIAL_SECRET = getSecret('CREDENTIAL_SECRET', SESSION_SECRET);
const CREDENTIAL_SALT = getSecret('CREDENTIAL_SALT', 'securescope-salt-v1');

const isCookieSecure = process.env.COOKIE_SECURE !== undefined
    ? process.env.COOKIE_SECURE === 'true'
    : isProduction;

module.exports = {
    SESSION_SECRET,
    CSRF_SECRET,
    CREDENTIAL_SECRET,
    CREDENTIAL_SALT,
    isProduction,
    isCookieSecure
};
