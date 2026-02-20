## 2025-02-23 - Inconsistent Authorization in API Routes
**Vulnerability:** `routes/vulnerabilities.js` endpoints (POST, PUT, DELETE) were missing `requirePermission` or `requireAdmin` middleware, unlike similar routes in `routes/exploits.js`.
**Learning:** Comments indicating security intent ("(admin only)") were present but not backed by code enforcement. The developer likely copy-pasted the structure but forgot the middleware or assumed `requireAuth` was sufficient.
**Prevention:** Use a centralized route definition or automated tests that verify authorization middleware presence on all state-changing routes.
