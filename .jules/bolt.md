## 2024-05-22 - SQLite Count Optimization
**Learning:** In SQLite (and generally), joining multiple 1:N relationships (scans -> results, scans -> vulns) creates a Cartesian product that explodes row counts before grouping. `COUNT(DISTINCT)` mitigates the result but not the intermediate processing cost.
**Action:** Use correlated subqueries in the `SELECT` clause for counts when fetching a limited set of parent rows (e.g., with `LIMIT 10`). This avoids the join explosion and is significantly faster in SQLite.

## 2024-05-22 - Environment Flakiness
**Learning:** The development environment is missing `supertest` in `node_modules` despite it being in `devDependencies`. This causes integration tests (`auth.test.js`, `scan_export.test.js`) to fail.
**Action:** Rely on unit tests and mocked dependencies for verification when integration tests are broken due to environment issues.
