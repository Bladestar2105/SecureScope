const bcrypt = require('bcrypt');
const { getDatabase } = require('../config/database');
const logger = require('./logger');

const SALT_ROUNDS = 10;

class UserService {
    // Authenticate user with username and password
    static async authenticate(username, password) {
        const db = getDatabase();
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

        if (!user) {
            logger.warn(`Login attempt with unknown username: ${username}`);
            return null;
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            logger.warn(`Failed login attempt for user: ${username}`);
            return null;
        }

        // Update last login timestamp
        db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

        logger.info(`User ${username} logged in successfully`);
        logger.audit('LOGIN_SUCCESS', { userId: user.id, username });

        return {
            id: user.id,
            username: user.username,
            forcePasswordChange: user.force_password_change === 1,
            createdAt: user.created_at,
            lastLogin: user.last_login
        };
    }

    // Change user password
    static async changePassword(userId, currentPassword, newPassword) {
        const db = getDatabase();
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

        if (!user) {
            throw new Error('Benutzer nicht gefunden');
        }

        // Verify current password
        const isValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isValid) {
            logger.warn(`Failed password change attempt for user ID: ${userId} - wrong current password`);
            throw new Error('Aktuelles Passwort ist falsch');
        }

        // Validate new password
        if (!newPassword || newPassword.length < 8) {
            throw new Error('Neues Passwort muss mindestens 8 Zeichen lang sein');
        }

        if (newPassword === currentPassword) {
            throw new Error('Neues Passwort muss sich vom aktuellen Passwort unterscheiden');
        }

        // Check password complexity
        const hasUpperCase = /[A-Z]/.test(newPassword);
        const hasLowerCase = /[a-z]/.test(newPassword);
        const hasNumbers = /\d/.test(newPassword);
        const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword);

        if (!(hasUpperCase && hasLowerCase && hasNumbers) && !hasSpecialChar) {
            throw new Error('Passwort muss Groß-/Kleinbuchstaben und Zahlen oder Sonderzeichen enthalten');
        }

        // Hash and update password
        const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
        db.prepare(
            'UPDATE users SET password_hash = ?, force_password_change = 0 WHERE id = ?'
        ).run(passwordHash, userId);

        logger.info(`Password changed for user ID: ${userId}`);
        logger.audit('PASSWORD_CHANGED', { userId, username: user.username });

        return true;
    }

    // Get user by ID
    static getById(userId) {
        const db = getDatabase();
        const user = db.prepare('SELECT id, username, created_at, last_login, force_password_change FROM users WHERE id = ?').get(userId);
        return user || null;
    }

    // Log audit event to database
    static logAudit(userId, action, details, ipAddress) {
        try {
            const db = getDatabase();
            db.prepare(
                'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
            ).run(userId, action, JSON.stringify(details), ipAddress);
        } catch (err) {
            logger.error('Failed to write audit log to database:', err);
        }
    }
}

module.exports = UserService;