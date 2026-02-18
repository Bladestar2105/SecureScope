const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { getDatabase } = require('../config/database');
const { requireAuth } = require('../middleware/auth');
const { requireAdmin, getUserPermissions } = require('../middleware/rbac');
const UserService = require('../services/userService');
const logger = require('../services/logger');

const SALT_ROUNDS = 10;

// All user management routes require authentication
router.use(requireAuth);

// GET /api/users - List all users (admin only)
router.get('/', requireAdmin, (req, res) => {
    try {
        const db = getDatabase();
        const users = db.prepare(`
            SELECT u.id, u.username, u.created_at, u.last_login, u.force_password_change,
                   GROUP_CONCAT(r.name) as roles
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `).all();

        const formattedUsers = users.map(u => ({
            ...u,
            roles: u.roles ? u.roles.split(',') : []
        }));

        res.json({ users: formattedUsers });
    } catch (err) {
        logger.error('User list error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/users/roles - List all available roles
router.get('/roles', requireAdmin, (req, res) => {
    try {
        const db = getDatabase();
        const roles = db.prepare('SELECT * FROM roles ORDER BY id').all();
        const formattedRoles = roles.map(r => ({
            ...r,
            permissions: JSON.parse(r.permissions)
        }));
        res.json({ roles: formattedRoles });
    } catch (err) {
        logger.error('Roles list error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/users - Create new user (admin only)
router.post('/', requireAdmin, async (req, res) => {
    try {
        const { username, password, roles } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
        }

        // Validate username
        const sanitizedUsername = username.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, '');
        if (sanitizedUsername.length < 3 || sanitizedUsername.length > 50) {
            return res.status(400).json({ error: 'Benutzername muss 3-50 Zeichen lang sein (nur a-z, 0-9, _, ., -)' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein' });
        }

        const db = getDatabase();

        // Check if username exists
        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(sanitizedUsername);
        if (existing) {
            return res.status(409).json({ error: 'Benutzername bereits vergeben' });
        }

        // Hash password and create user
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const result = db.prepare(
            'INSERT INTO users (username, password_hash, force_password_change) VALUES (?, ?, 1)'
        ).run(sanitizedUsername, passwordHash);

        const userId = result.lastInsertRowid;

        // Assign roles
        if (roles && Array.isArray(roles) && roles.length > 0) {
            const roleStmt = db.prepare(
                'INSERT INTO user_roles (user_id, role_id, assigned_by) SELECT ?, id, ? FROM roles WHERE name = ?'
            );
            for (const roleName of roles) {
                roleStmt.run(userId, req.session.userId, roleName);
            }
        } else {
            // Default role: viewer
            const viewerRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('viewer');
            if (viewerRole) {
                db.prepare(
                    'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)'
                ).run(userId, viewerRole.id, req.session.userId);
            }
        }

        UserService.logAudit(req.session.userId, 'USER_CREATED', {
            newUserId: userId, username: sanitizedUsername, roles: roles || ['viewer']
        }, req.ip);

        logger.info(`User created: ${sanitizedUsername} (ID: ${userId}) by ${req.session.username}`);

        res.json({
            success: true,
            user: { id: userId, username: sanitizedUsername, roles: roles || ['viewer'] }
        });
    } catch (err) {
        logger.error('User create error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// PUT /api/users/:id - Update user (admin only)
router.put('/:id', requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Ungültige Benutzer-ID' });
        }

        const db = getDatabase();
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        if (!user) {
            return res.status(404).json({ error: 'Benutzer nicht gefunden' });
        }

        const { password, roles, forcePasswordChange } = req.body;

        // Update password if provided
        if (password) {
            if (password.length < 8) {
                return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein' });
            }
            const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
            db.prepare('UPDATE users SET password_hash = ?, force_password_change = 1 WHERE id = ?')
                .run(passwordHash, userId);
        }

        // Update force password change flag
        if (typeof forcePasswordChange === 'boolean') {
            db.prepare('UPDATE users SET force_password_change = ? WHERE id = ?')
                .run(forcePasswordChange ? 1 : 0, userId);
        }

        // Update roles if provided
        if (roles && Array.isArray(roles)) {
            // Prevent removing admin role from the last admin
            if (userId === 1 && !roles.includes('admin')) {
                return res.status(400).json({ error: 'Der Hauptadministrator muss die Admin-Rolle behalten' });
            }

            // Remove existing roles
            db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(userId);

            // Assign new roles
            const roleStmt = db.prepare(
                'INSERT INTO user_roles (user_id, role_id, assigned_by) SELECT ?, id, ? FROM roles WHERE name = ?'
            );
            for (const roleName of roles) {
                roleStmt.run(userId, req.session.userId, roleName);
            }
        }

        UserService.logAudit(req.session.userId, 'USER_UPDATED', {
            targetUserId: userId, changes: { roles, passwordChanged: !!password }
        }, req.ip);

        logger.info(`User ${userId} updated by ${req.session.username}`);
        res.json({ success: true, message: 'Benutzer aktualisiert' });
    } catch (err) {
        logger.error('User update error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// DELETE /api/users/:id - Delete user (admin only)
router.delete('/:id', requireAdmin, (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Ungültige Benutzer-ID' });
        }

        // Prevent deleting the primary admin
        if (userId === 1) {
            return res.status(400).json({ error: 'Der Hauptadministrator kann nicht gelöscht werden' });
        }

        // Prevent self-deletion
        if (userId === req.session.userId) {
            return res.status(400).json({ error: 'Sie können sich nicht selbst löschen' });
        }

        const db = getDatabase();
        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
        if (!user) {
            return res.status(404).json({ error: 'Benutzer nicht gefunden' });
        }

        db.prepare('DELETE FROM users WHERE id = ?').run(userId);

        UserService.logAudit(req.session.userId, 'USER_DELETED', {
            deletedUserId: userId, deletedUsername: user.username
        }, req.ip);

        logger.info(`User ${user.username} (ID: ${userId}) deleted by ${req.session.username}`);
        res.json({ success: true, message: `Benutzer "${user.username}" gelöscht` });
    } catch (err) {
        logger.error('User delete error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/users/me/permissions - Get current user's permissions
router.get('/me/permissions', (req, res) => {
    try {
        const { roles, permissions } = getUserPermissions(req.session.userId);
        res.json({ roles, permissions });
    } catch (err) {
        logger.error('Permissions error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

module.exports = router;