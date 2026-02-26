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

        // Ensure scan_vulnerabilities table exists (should be handled by schema now, but safe to keep)
        // We rely on schema initialization for table creation now.

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

        // Optimization: Prepare statements once outside the loop
        const cpeMatchStmt = db.prepare(`
            SELECT cve_id, title, severity, cvss_score
            FROM cve_entries
            WHERE affected_products LIKE ? AND state = 'PUBLISHED'
            ORDER BY cvss_score DESC LIMIT 30
        `);

        const productMatchStmt = db.prepare(`
            SELECT cve_id, title, severity, cvss_score
            FROM cve_entries
            WHERE (affected_products LIKE ? OR title LIKE ?) AND state = 'PUBLISHED'
            ORDER BY cvss_score DESC LIMIT 20
        `);

        // Optimization: Cache query results
        const cpeQueryCache = new Map();
        const productQueryCache = new Map();

        const insertItems = [];
        const seenCVEs = new Set(); // Avoid duplicates per scan_result

        for (const result of scanResults) {
            const resultKey = result.id;

            // Strategy 1: Match by CPE (most accurate, confidence 90)
            if (result.service_cpe) {
                const cpes = result.service_cpe.split(',');
                for (const cpe of cpes) {
                    // Extract vendor:product from CPE (e.g. cpe:/a:apache:http_server -> apache:http_server)
                    const cpeParts = cpe.trim().split(':');
                    let searchTerm = '';
                    if (cpeParts.length >= 4) {
                        searchTerm = cpeParts.slice(2, 5).join(':'); // vendor:product:version
                    } else if (cpeParts.length >= 3) {
                        searchTerm = cpeParts.slice(2, 4).join(':'); // vendor:product
                    }

                    if (!searchTerm || searchTerm.length < 3) continue;

                    try {
                        let cveResults;
                        if (cpeQueryCache.has(searchTerm)) {
                            cveResults = cpeQueryCache.get(searchTerm);
                        } else {
                            cveResults = cpeMatchStmt.all(`%${searchTerm}%`);
                            cpeQueryCache.set(searchTerm, cveResults);
                        }

                        for (const cve of cveResults) {
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
                    } catch (e) {
                        logger.warn(`CPE matching error for ${searchTerm}:`, e.message);
                    }
                }
            }

            // Strategy 2: Match by product name (confidence 60)
            if (result.service_product) {
                const product = result.service_product.trim();
                if (product.length < 3) continue;

                try {
                    let productResults;
                    if (productQueryCache.has(product)) {
                        productResults = productQueryCache.get(product);
                    } else {
                        productResults = productMatchStmt.all(`%${product}%`, `%${product}%`);
                        productQueryCache.set(product, productResults);
                    }

                    for (const cve of productResults) {
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
                } catch (e) {
                    logger.warn(`Product matching error for ${product}:`, e.message);
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
