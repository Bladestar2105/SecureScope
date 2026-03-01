## 2025-02-23 - Inconsistent Authorization in API Routes
**Vulnerability:** `routes/vulnerabilities.js` endpoints (POST, PUT, DELETE) were missing `requirePermission` or `requireAdmin` middleware, unlike similar routes in `routes/exploits.js`.
**Learning:** Comments indicating security intent ("(admin only)") were present but not backed by code enforcement. The developer likely copy-pasted the structure but forgot the middleware or assumed `requireAuth` was sufficient.
**Prevention:** Use a centralized route definition or automated tests that verify authorization middleware presence on all state-changing routes.
## 2025-02-23 - Inconsistent Authorization in Scan Routes
**Vulnerability:** `routes/scan.js` endpoints (POST, DELETE, GET) were missing `requirePermission` middleware. Any authenticated user could start, stop, or delete scans, violating the role-based access control (RBAC) model.
**Learning:** Route definitions that only include `requireAuth` do not enforce specific permissions. This allows low-privilege users (e.g. 'viewer') to execute state-changing operations.
**Prevention:** Apply specific `requirePermission` middleware to every route based on the intended access level.
