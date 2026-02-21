jest.mock('../config/database', () => ({
    getDatabase: jest.fn()
}));
jest.mock('../services/logger', () => ({
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    audit: jest.fn()
}));

const { getUserPermissions, requirePermission, requireAdmin, hasPermission } = require('../middleware/rbac');
const { getDatabase } = require('../config/database');
const logger = require('../services/logger');

describe('RBAC Middleware', () => {
    let mockDb;

    beforeEach(() => {
        jest.clearAllMocks();
        mockDb = {
            prepare: jest.fn().mockReturnThis(),
            all: jest.fn(),
            get: jest.fn()
        };
        getDatabase.mockReturnValue(mockDb);
    });

    describe('getUserPermissions', () => {
        test('should return roles and permissions for a user', () => {
            const userId = 1;
            const roles = [
                { name: 'admin', permissions: '["scan:start", "scan:stop"]' },
                { name: 'analyst', permissions: '["scan:view"]' }
            ];
            mockDb.all.mockReturnValue(roles);

            const result = getUserPermissions(userId);

            expect(result.roles).toEqual(['admin', 'analyst']);
            expect(result.permissions).toEqual(expect.arrayContaining(['scan:start', 'scan:stop', 'scan:view']));
            expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('SELECT r.name, r.permissions'));
        });

        test('should handle malformed JSON in permissions', () => {
            const userId = 1;
            const roles = [
                { name: 'badrole', permissions: 'invalid-json' }
            ];
            mockDb.all.mockReturnValue(roles);

            const result = getUserPermissions(userId);

            expect(result.roles).toEqual(['badrole']);
            expect(result.permissions).toEqual([]);
            expect(logger.error).toHaveBeenCalled();
        });
    });

    describe('requirePermission', () => {
        let req, res, next;

        beforeEach(() => {
            req = {
                session: { userId: 1, username: 'testuser' }
            };
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis()
            };
            next = jest.fn();
        });

        test('should return 401 if not authenticated', () => {
            req.session = null;
            const middleware = requirePermission('scan:start');
            middleware(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });

        test('should call next if user has permission', () => {
            mockDb.all.mockReturnValue([{ name: 'analyst', permissions: '["scan:view"]' }]);
            const middleware = requirePermission('scan:view');
            middleware(req, res, next);

            expect(next).toHaveBeenCalled();
            expect(req.userRoles).toEqual(['analyst']);
            expect(req.userPermissions).toEqual(['scan:view']);
        });

        test('should call next if user is admin (admin bypass)', () => {
            mockDb.all.mockReturnValue([{ name: 'admin', permissions: '[]' }]);
            const middleware = requirePermission('anything');
            middleware(req, res, next);

            expect(next).toHaveBeenCalled();
        });

        test('should return 403 if user lacks permission', () => {
            mockDb.all.mockReturnValue([{ name: 'viewer', permissions: '["scan:view"]' }]);
            const middleware = requirePermission('scan:start');
            middleware(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(next).not.toHaveBeenCalled();
            expect(logger.warn).toHaveBeenCalled();
        });

        test('should work with multiple required permissions (OR logic)', () => {
             mockDb.all.mockReturnValue([{ name: 'analyst', permissions: '["scan:view"]' }]);
             const middleware = requirePermission('scan:start', 'scan:view');
             middleware(req, res, next);

             expect(next).toHaveBeenCalled();
        });
    });

    describe('requireAdmin', () => {
        let req, res, next;

        beforeEach(() => {
            req = {
                session: { userId: 1, username: 'testuser' }
            };
            res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis()
            };
            next = jest.fn();
        });

        test('should return 401 if not authenticated', () => {
            req.session = null;
            requireAdmin(req, res, next);
            expect(res.status).toHaveBeenCalledWith(401);
        });

        test('should call next if user is admin', () => {
            mockDb.all.mockReturnValue([{ name: 'admin', permissions: '[]' }]);
            requireAdmin(req, res, next);
            expect(next).toHaveBeenCalled();
        });

        test('should return 403 if user is not admin', () => {
            mockDb.all.mockReturnValue([{ name: 'analyst', permissions: '[]' }]);
            requireAdmin(req, res, next);
            expect(res.status).toHaveBeenCalledWith(403);
            expect(logger.warn).toHaveBeenCalled();
        });
    });

    describe('hasPermission', () => {
        test('should return true if user has permission', () => {
            mockDb.all.mockReturnValue([{ name: 'analyst', permissions: '["scan:view"]' }]);
            expect(hasPermission(1, 'scan:view')).toBe(true);
        });

        test('should return true if user is admin', () => {
            mockDb.all.mockReturnValue([{ name: 'admin', permissions: '[]' }]);
            expect(hasPermission(1, 'anything')).toBe(true);
        });

        test('should return false if user lacks permission', () => {
            mockDb.all.mockReturnValue([{ name: 'viewer', permissions: '["scan:view"]' }]);
            expect(hasPermission(1, 'scan:start')).toBe(false);
        });
    });
});
