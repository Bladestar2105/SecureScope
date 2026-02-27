const { getDatabase } = require('../config/database');
const logger = require('./logger');

class CVEService {
    /**
     * Match scan results against CVE database using detected service versions
     */
    static matchCVEs(scanId) {
        const db = getDatabase();
        const matches = [];

        // Check if cve_entries table exists and has data
        let cveCount = 0;
        try {
            cveCount = db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;
        } catch (e) {
            logger.warn('CVE table not available for matching');
            return matches;
        }

        if (cveCount === 0) {
            logger.info('No CVEs in database, skipping CVE matching');
            return matches;
        }

        // Prepare insert statement
        const insertStmt = db.prepare(`
            INSERT OR IGNORE INTO scan_vulnerabilities
            (scan_id, scan_result_id, cve_id, title, severity, cvss_score, matched_service, matched_version, match_confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        // Get scan results with service info
        const scanResults = db.prepare(`
            SELECT id, port, service, service_product, service_version, service_cpe, banner
            FROM scan_results WHERE scan_id = ? AND state = 'open'
        `).all(scanId);

        // --- Optimization: Bulk Fetching Strategy ---
        // Collect all unique search terms first to avoid N+1 queries
        const cpeSearchTerms = new Set();
        const productSearchTerms = new Set();

        for (const result of scanResults) {
            // Collect CPE terms
            if (result.service_cpe) {
                const cpes = result.service_cpe.split(',');
                for (const cpe of cpes) {
                    const cpeParts = cpe.trim().split(':');
                    if (cpeParts.length >= 4) {
                        cpeSearchTerms.add(cpeParts.slice(2, 5).join(':')); // vendor:product:version
                    } else if (cpeParts.length >= 3) {
                        cpeSearchTerms.add(cpeParts.slice(2, 4).join(':')); // vendor:product
                    }
                }
            }
            // Collect Product terms
            if (result.service_product) {
                const product = result.service_product.trim();
                if (product.length >= 3) {
                    productSearchTerms.add(product);
                }
            }
        }

        // Pre-fetch CVEs for all terms
        // Map<searchTerm, Array<CVE>>
        const cveCache = new Map();

        // Helper to fetch and cache
        const fetchAndCache = (terms, queryTemplate, type) => {
            if (terms.size === 0) return;
            const termsArray = Array.from(terms);

            // SQLite has a limit on parameters, so we might need to batch if there are too many terms.
            // A safe batch size is around 100-500.
            const BATCH_SIZE = 50;

            for (let i = 0; i < termsArray.length; i += BATCH_SIZE) {
                const batch = termsArray.slice(i, i + BATCH_SIZE);
                // Construct dynamic query
                // We use LIKE for each term combined with OR
                const conditions = batch.map(() => `affected_products LIKE ?`).join(' OR ');
                const query = `
                    SELECT cve_id, title, severity, cvss_score, affected_products
                    FROM cve_entries
                    WHERE (${conditions}) AND state = 'PUBLISHED'
                    ORDER BY cvss_score DESC
                `;

                // Add % wildcards to params
                const params = batch.map(t => `%${t}%`);

                try {
                    const results = db.prepare(query).all(...params);

                    // Distribute results into cache based on which term matched
                    // Since a CVE can match multiple terms, we check each term against the result
                    for (const row of results) {
                        // Optimization: Lowercase once per row
                        const affectedProductsLower = row.affected_products ? row.affected_products.toLowerCase() : '';

                        for (const term of batch) {
                            // Case-insensitive check to match SQLite LIKE behavior
                            const termLower = term.toLowerCase();

                            if (affectedProductsLower.includes(termLower)) {
                                if (!cveCache.has(term)) {
                                    cveCache.set(term, []);
                                }
                                // Dedup check
                                const list = cveCache.get(term);
                                if (!list.find(c => c.cve_id === row.cve_id)) {
                                    list.push(row);
                                }
                            }
                        }
                    }
                } catch (e) {
                    logger.warn(`Bulk CVE fetch failed for ${type}:`, e.message);
                }
            }
        };

        // Execute bulk fetches
        if (cpeSearchTerms.size > 0) {
            // For CPEs, we check affected_products LIKE %term%
            fetchAndCache(cpeSearchTerms, null, 'CPE');
        }

        if (productSearchTerms.size > 0) {
            // For Products, we check (affected_products LIKE %term% OR title LIKE %term%)
            // We reuse the helper but need custom query logic if we want to search title too.
            // To keep it simple and consistent with previous logic which had separate queries:
            // The previous productMatchStmt was: WHERE (affected_products LIKE ? OR title LIKE ?)

            const termsArray = Array.from(productSearchTerms);
            const BATCH_SIZE = 50;

            for (let i = 0; i < termsArray.length; i += BATCH_SIZE) {
                const batch = termsArray.slice(i, i + BATCH_SIZE);
                const conditions = batch.map(() => `(affected_products LIKE ? OR title LIKE ?)`).join(' OR ');
                const query = `
                    SELECT cve_id, title, severity, cvss_score, affected_products
                    FROM cve_entries
                    WHERE (${conditions}) AND state = 'PUBLISHED'
                    ORDER BY cvss_score DESC
                `;

                const params = [];
                batch.forEach(t => {
                    params.push(`%${t}%`);
                    params.push(`%${t}%`);
                });

                try {
                    const results = db.prepare(query).all(...params);
                    for (const row of results) {
                        // Optimization: Lowercase once per row
                        const affectedProductsLower = row.affected_products ? row.affected_products.toLowerCase() : '';
                        const titleLower = row.title ? row.title.toLowerCase() : '';

                        for (const term of batch) {
                            // Case-insensitive check to match SQLite LIKE behavior
                            const termLower = term.toLowerCase();

                            if (affectedProductsLower.includes(termLower) || titleLower.includes(termLower)) {
                                if (!cveCache.has(term)) {
                                    cveCache.set(term, []);
                                }
                                const list = cveCache.get(term);
                                if (!list.find(c => c.cve_id === row.cve_id)) {
                                    list.push(row);
                                }
                            }
                        }
                    }
                } catch (e) {
                    logger.warn(`Bulk CVE fetch failed for Product:`, e.message);
                }
            }
        }

        const insertItems = [];
        const seenCVEs = new Set(); // Avoid duplicates per scan_result

        for (const result of scanResults) {
            const resultKey = result.id;

            // Strategy 1: Match by CPE (most accurate, confidence 90)
            if (result.service_cpe) {
                const cpes = result.service_cpe.split(',');
                for (const cpe of cpes) {
                    const cpeParts = cpe.trim().split(':');
                    let searchTerm = '';
                    if (cpeParts.length >= 4) {
                        searchTerm = cpeParts.slice(2, 5).join(':'); // vendor:product:version
                    } else if (cpeParts.length >= 3) {
                        searchTerm = cpeParts.slice(2, 4).join(':'); // vendor:product
                    }

                    if (!searchTerm || searchTerm.length < 3) continue;

                    const cveResults = cveCache.get(searchTerm) || [];

                    // Limit to top 30 as per original logic
                    const topResults = cveResults.slice(0, 30);

                    for (const cve of topResults) {
                        const key = `${resultKey}:${cve.cve_id}`;
                        if (seenCVEs.has(key)) continue;
                        seenCVEs.add(key);

                        insertItems.push({
                            scan_id: scanId, scan_result_id: result.id,
                            cve_id: cve.cve_id, title: cve.title,
                            severity: cve.severity, cvss_score: cve.cvss_score,
                            matched_service: result.service_product || result.service,
                            matched_version: result.service_version || '',
                            match_confidence: 90
                        });
                        matches.push({ ...cve, confidence: 90, matched_by: 'cpe' });
                    }
                }
            }

            // Strategy 2: Match by product name (confidence 60)
            if (result.service_product) {
                const product = result.service_product.trim();
                if (product.length < 3) continue;

                const cveResults = cveCache.get(product) || [];

                // Limit to top 20 as per original logic
                const topResults = cveResults.slice(0, 20);

                for (const cve of topResults) {
                    const key = `${resultKey}:${cve.cve_id}`;
                    if (seenCVEs.has(key)) continue;
                    seenCVEs.add(key);

                    insertItems.push({
                        scan_id: scanId, scan_result_id: result.id,
                        cve_id: cve.cve_id, title: cve.title,
                        severity: cve.severity, cvss_score: cve.cvss_score,
                        matched_service: product,
                        matched_version: result.service_version || '',
                        match_confidence: 60
                    });
                    matches.push({ ...cve, confidence: 60, matched_by: 'product' });
                }
            }
        }

        // Batch insert all matches
        if (insertItems.length > 0) {
            try {
                const insertAll = db.transaction((items) => {
                    for (const item of items) {
                        insertStmt.run(
                            item.scan_id, item.scan_result_id, item.cve_id,
                            item.title, item.severity, item.cvss_score,
                            item.matched_service, item.matched_version, item.match_confidence
                        );
                    }
                });
                insertAll(insertItems);
                logger.info(`Scan ${scanId}: Inserted ${insertItems.length} CVE matches`);
            } catch (e) {
                logger.error('Error inserting CVE matches:', e);
            }
        }

        return matches;
    }

    // Get CVE matches for a scan
    static getScanCVEs(scanId) {
        const db = getDatabase();
        try {
            return db.prepare(`
                SELECT sv.*, sr.port, sr.service, sr.service_product, sr.service_version, sr.ip_address
                FROM scan_vulnerabilities sv
                JOIN scan_results sr ON sv.scan_result_id = sr.id
                WHERE sv.scan_id = ?
                ORDER BY sv.cvss_score DESC
            `).all(scanId);
        } catch (e) {
            return [];
        }
    }

    // Get CVE summary for a scan
    static getScanCVESummary(scanId) {
        const db = getDatabase();
        try {
            // Optimization: Combine 5 queries into 1 using conditional aggregation
            const summary = db.prepare(`
                SELECT
                    COUNT(*) as total,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
                    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
                    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low
                FROM scan_vulnerabilities
                WHERE scan_id = ?
            `).get(scanId);
            return summary;
        } catch (e) {
            return { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
        }
    }
}

module.exports = CVEService;