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

        const uniqueCpeTerms = new Map(); // searchTerm -> Array of results
        const uniqueProductTerms = new Map(); // searchTerm -> Array of results

        for (const result of scanResults) {
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

                    if (searchTerm && searchTerm.length >= 3) {
                        if (!uniqueCpeTerms.has(searchTerm)) {
                            uniqueCpeTerms.set(searchTerm, []);
                        }
                        uniqueCpeTerms.get(searchTerm).push(result);
                    }
                }
            }

            // Strategy 2: Match by product name (confidence 60)
            if (result.service_product) {
                const product = result.service_product.trim();
                if (product.length >= 3) {
                    if (!uniqueProductTerms.has(product)) {
                        uniqueProductTerms.set(product, []);
                    }
                    uniqueProductTerms.get(product).push(result);
                }
            }
        }

        const insertItems = [];
        const seenCVEs = new Set(); // Avoid duplicates per scan_result

        // Bulk match CPEs
        if (uniqueCpeTerms.size > 0) {
            const terms = Array.from(uniqueCpeTerms.keys());
            const CHUNK_SIZE = 50;
            for (let i = 0; i < terms.length; i += CHUNK_SIZE) {
                const chunk = terms.slice(i, i + CHUNK_SIZE);
                const placeholders = chunk.map(() => 'affected_products LIKE ?').join(' OR ');
                try {
                    const bulkResults = db.prepare(`
                        SELECT cve_id, title, severity, cvss_score, affected_products
                        FROM cve_entries
                        WHERE (${placeholders}) AND state = 'PUBLISHED'
                    `).all(chunk.map(t => `%${t}%`));

                    for (const searchTerm of chunk) {
                        const resultsUsingThisTerm = uniqueCpeTerms.get(searchTerm);
                        const filteredMatches = bulkResults
                            .filter(cve => cve.affected_products && cve.affected_products.toLowerCase().includes(searchTerm.toLowerCase()))
                            .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
                            .slice(0, 30);

                        for (const cve of filteredMatches) {
                            for (const result of resultsUsingThisTerm) {
                                const key = `${result.id}:${cve.cve_id}`;
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
                } catch (e) {
                    logger.warn(`Bulk CPE matching error: ${e.message}`);
                }
            }
        }

        // Bulk match Products
        if (uniqueProductTerms.size > 0) {
            const terms = Array.from(uniqueProductTerms.keys());
            const CHUNK_SIZE = 25; // Each term has 2 placeholders
            for (let i = 0; i < terms.length; i += CHUNK_SIZE) {
                const chunk = terms.slice(i, i + CHUNK_SIZE);
                const placeholders = chunk.map(() => '(affected_products LIKE ? OR title LIKE ?)').join(' OR ');
                try {
                    const params = [];
                    for (const t of chunk) {
                        params.push(`%${t}%`, `%${t}%`);
                    }
                    const bulkResults = db.prepare(`
                        SELECT cve_id, title, severity, cvss_score, affected_products
                        FROM cve_entries
                        WHERE (${placeholders}) AND state = 'PUBLISHED'
                    `).all(params);

                    for (const searchTerm of chunk) {
                        const resultsUsingThisTerm = uniqueProductTerms.get(searchTerm);
                        const filteredMatches = bulkResults
                            .filter(cve =>
                                (cve.affected_products && cve.affected_products.toLowerCase().includes(searchTerm.toLowerCase())) ||
                                (cve.title && cve.title.toLowerCase().includes(searchTerm.toLowerCase()))
                            )
                            .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
                            .slice(0, 20);

                        for (const cve of filteredMatches) {
                            for (const result of resultsUsingThisTerm) {
                                const key = `${result.id}:${cve.cve_id}`;
                                if (seenCVEs.has(key)) continue;
                                seenCVEs.add(key);

                                insertItems.push({
                                    scan_id: scanId, scan_result_id: result.id,
                                    cve_id: cve.cve_id, title: cve.title,
                                    severity: cve.severity, cvss_score: cve.cvss_score,
                                    matched_service: searchTerm,
                                    matched_version: result.service_version || '',
                                    match_confidence: 60
                                });
                                matches.push({ ...cve, confidence: 60, matched_by: 'product' });
                            }
                        }
                    }
                } catch (e) {
                    logger.warn(`Bulk Product matching error: ${e.message}`);
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
            const total = db.prepare('SELECT COUNT(*) as c FROM scan_vulnerabilities WHERE scan_id = ?').get(scanId).c;
            const critical = db.prepare("SELECT COUNT(*) as c FROM scan_vulnerabilities WHERE scan_id = ? AND severity = 'critical'").get(scanId).c;
            const high = db.prepare("SELECT COUNT(*) as c FROM scan_vulnerabilities WHERE scan_id = ? AND severity = 'high'").get(scanId).c;
            const medium = db.prepare("SELECT COUNT(*) as c FROM scan_vulnerabilities WHERE scan_id = ? AND severity = 'medium'").get(scanId).c;
            const low = db.prepare("SELECT COUNT(*) as c FROM scan_vulnerabilities WHERE scan_id = ? AND severity = 'low'").get(scanId).c;
            return { total, critical, high, medium, low };
        } catch (e) {
            return { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
        }
    }
}

module.exports = CVEService;
