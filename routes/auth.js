const express = require('express');
const router = express.Router();
const UserService = require('../services/userService');
const { requireAuth, generateCsrfToken } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/rateLimit');
const logger = require('../services/logger');

// POST /api/auth/login
router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
        }

        // Sanitize input
        const sanitizedUsername = username.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '');

        if (sanitizedUsername !== username.trim().toLowerCase()) {
            logger.warn(`Suspicious login attempt with special characters from ${req.ip}`);
            return res.status(400).json({ error: 'Ungültiger Benutzername' });
        }

        const user = await UserService.authenticate(sanitizedUsername, password);

        if (!user) {
            UserService.logAudit(null, 'LOGIN_FAILED', { username: sanitizedUsername }, req.ip);
            return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
        }

        // Set session data
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.forcePasswordChange = user.forcePasswordChange;
        req.session.lastActivity = Date.now();

        // Generate CSRF token
        const csrfToken = generateCsrfToken(req);

        UserService.logAudit(user.id, 'LOGIN_SUCCESS', {}, req.ip);

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                forcePasswordChange: user.forcePasswordChange
            },
            csrfToken
        });
    } catch (err) {
        logger.error('Login error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
    const userId = req.session?.userId;
    const username = req.session?.username;

    if (userId) {
        UserService.logAudit(userId, 'LOGOUT', {}, req.ip);
        logger.info(`User ${username} logged out`);
    }

    req.session.destroy((err) => {
        if (err) {
            logger.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Fehler beim Abmelden' });
        }
        res.clearCookie('securescope.sid');
        res.json({ success: true, message: 'Erfolgreich abgemeldet' });
    });
});

// GET /api/auth/status
router.get('/status', (req, res) => {
    if (req.session && req.session.userId) {
        const user = UserService.getById(req.session.userId);
        if (!user) {
            return res.json({ authenticated: false });
        }

        // Regenerate CSRF token only if not exists
        const csrfToken = req.session.csrfToken || generateCsrfToken(req);

        return res.json({
            authenticated: true,
            user: {
                id: user.id,
                username: user.username,
                forcePasswordChange: user.force_password_change === 1
            },
            csrfToken
        });
    }
    res.json({ authenticated: false });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: 'Neue Passwörter stimmen nicht überein' });
        }

        await UserService.changePassword(req.session.userId, currentPassword, newPassword);

        // Update session
        req.session.forcePasswordChange = false;

        UserService.logAudit(req.session.userId, 'PASSWORD_CHANGED', {}, req.ip);

        res.json({ success: true, message: 'Passwort erfolgreich geändert' });
    } catch (err) {
        logger.error('Password change error:', err);
        if (err.message.includes('Passwort') || err.message.includes('Zeichen')) {
            return res.status(400).json({ error: err.message });
        }
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

module.exports = router;