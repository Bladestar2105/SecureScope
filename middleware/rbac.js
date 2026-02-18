const { getDatabase } = require('../config/database');
const logger = require('../services/logger');

// Get user roles and permissions
function getUserPermissions(userId) {
    const db = getDatabase();
    const roles = db.prepare(`
        SELECT r.name, r.permissions
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ?
    `).all(userId);

    const permissions = new Set();
    const roleNames = [];

    for (const role of roles) {
        roleNames.push(role.name);
        try {
            const perms = JSON.parse(role.permissions);
            perms.forEach(p => permissions.add(p));
        } catch (e) {
            logger.error(`Failed to parse permissions for role ${role.name}:`, e);
        }
    }

    return { roles: roleNames, permissions: Array.from(permissions) };
}

// Middleware: require specific permission
function requirePermission(...requiredPermissions) {
    return (req, res, next) => {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: 'Nicht authentifiziert' });
        }

        const { roles, permissions } = getUserPermissions(req.session.userId);

        // Admin role has all permissions
        if (roles.includes('admin')) {
            req.userRoles = roles;
            req.userPermissions = permissions;
            return next();
        }

        // Check if user has at least one of the required permissions
        const hasPermission = requiredPermissions.some(p => permissions.includes(p));

        if (!hasPermission) {
            logger.warn(`Permission denied for user ${req.session.username}: requires [${requiredPermissions.join(', ')}], has [${permissions.join(', ')}]`);
            return res.status(403).json({ 
                error: 'Keine Berechtigung für diese Aktion',
                required: requiredPermissions
            });
        }

        req.userRoles = roles;
        req.userPermissions = permissions;
        next();
    };
}

// Middleware: require admin role
function requireAdmin(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Nicht authentifiziert' });
    }

    const { roles } = getUserPermissions(req.session.userId);

    if (!roles.includes('admin')) {
        logger.warn(`Admin access denied for user ${req.session.username}`);
        return res.status(403).json({ error: 'Administrator-Berechtigung erforderlich' });
    }

    req.userRoles = roles;
    next();
}

// Helper: check if user has permission (non-middleware)
function hasPermission(userId, permission) {
    const { roles, permissions } = getUserPermissions(userId);
    if (roles.includes('admin')) return true;
    return permissions.includes(permission);
}

module.exports = {
    getUserPermissions,
    requirePermission,
    requireAdmin,
    hasPermission
};