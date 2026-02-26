## 2024-05-22 - SQLite Count Optimization
**Learning:** In SQLite (and generally), joining multiple 1:N relationships (scans -> results, scans -> vulns) creates a Cartesian product that explodes row counts before grouping. `COUNT(DISTINCT)` mitigates the result but not the intermediate processing cost.
**Action:** Use correlated subqueries in the `SELECT` clause for counts when fetching a limited set of parent rows (e.g., with `LIMIT 10`). This avoids the join explosion and is significantly faster in SQLite.

## 2024-05-22 - Environment Flakiness
**Learning:** The development environment is missing `supertest` in `node_modules` despite it being in `devDependencies`. This causes integration tests (`auth.test.js`, `scan_export.test.js`) to fail.
**Action:** Rely on unit tests and mocked dependencies for verification when integration tests are broken due to environment issues.

## 2024-05-23 - SQLite Correlated Subqueries vs Joins
**Learning:** In SQLite, when fetching a limited number of parent rows (e.g., `LIMIT 10`), using correlated subqueries in the `SELECT` clause for counting children is significantly faster (97% improvement observed) than `LEFT JOIN` + `GROUP BY`. The latter causes a Cartesian product explosion before grouping.
**Action:** Prefer `(SELECT COUNT(*) FROM child WHERE child.parent_id = parent.id)` over `LEFT JOIN` when the parent query has a small `LIMIT`.

## 2024-05-24 - Optimizing Multiple Database Queries
**Learning:** Consolidating multiple `COUNT` queries with different `WHERE` clauses into a single query using `COUNT(CASE WHEN ...)` or `SUM(CASE WHEN ...)` significantly reduces database overhead.
**Action:** When needing multiple counts from the same table with different conditions, use conditional aggregation in a single query instead of separate queries.
