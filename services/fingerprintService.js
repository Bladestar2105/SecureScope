const { getDatabase } = require('../config/database');
const logger = require('./logger');

class FingerprintService {

    // Get all fingerprints from the database
    static getAll(filters = {}) {
        const db = getDatabase();
        let query = 'SELECT * FROM fingerprints WHERE 1=1';
        const params = [];

        if (filters.port) {
            query += ' AND port = ?';
            params.push(filters.port);
        }
        if (filters.service) {
            query += ' AND LOWER(service_name) LIKE LOWER(?)';
            params.push(`%${filters.service}%`);
        }
        if (filters.os) {
            query += ' AND LOWER(os_family) LIKE LOWER(?)';
            params.push(`%${filters.os}%`);
        }
        if (filters.search) {
            query += ' AND (service_name LIKE ? OR description LIKE ? OR cpe LIKE ?)';
            const term = `%${filters.search}%`;
            params.push(term, term, term);
        }

        query += ' ORDER BY port ASC, service_name ASC';

        const page = filters.page || 1;
        const limit = filters.limit || 50;
        const offset = (page - 1) * limit;

        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as count');
        const total = db.prepare(countQuery).get(...params);

        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const results = db.prepare(query).all(...params);

        return {
            fingerprints: results,
            pagination: {
                page, limit,
                total: total.count,
                totalPages: Math.ceil(total.count / limit)
            }
        };
    }

    // Get fingerprint by ID
    static getById(id) {
        const db = getDatabase();
        return db.prepare('SELECT * FROM fingerprints WHERE id = ?').get(id);
    }

    // Get fingerprints for a specific port
    static getByPort(port) {
        const db = getDatabase();
        return db.prepare('SELECT * FROM fingerprints WHERE port = ? ORDER BY confidence DESC').all(port);
    }

    // Match scan results against fingerprint database
    static matchScanResults(scanId) {
        const db = getDatabase();
        const scanResults = db.prepare('SELECT * FROM scan_results WHERE scan_id = ? AND state = ?').all(scanId, 'open');

        if (scanResults.length === 0) return [];

        const matches = [];
        const insertStmt = db.prepare(`
            INSERT INTO scan_fingerprints (scan_id, scan_result_id, detected_service, detected_version, detected_os, cpe, banner, confidence, fingerprint_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        // Batch pre-fetch fingerprints for all unique ports
        const uniquePorts = [...new Set(scanResults.map(r => r.port))];
        const fingerprintMap = new Map();

        // SQLite has a limit on the number of parameters (usually 999)
        const CHUNK_SIZE = 900;
        for (let i = 0; i < uniquePorts.length; i += CHUNK_SIZE) {
            const chunk = uniquePorts.slice(i, i + CHUNK_SIZE);
            const placeholders = chunk.map(() => '?').join(',');
            const fps = db.prepare(`SELECT * FROM fingerprints WHERE port IN (${placeholders}) ORDER BY confidence DESC`).all(...chunk);

            for (const fp of fps) {
                if (!fingerprintMap.has(fp.port)) {
                    fingerprintMap.set(fp.port, []);
                }
                fingerprintMap.get(fp.port).push(fp);
            }
        }

        const matchAll = db.transaction(() => {
            for (const result of scanResults) {
                // Find fingerprints matching this port from our pre-fetched map
                const fps = fingerprintMap.get(result.port) || [];

                if (fps.length > 0) {
                    // Use the highest-confidence match
                    const bestMatch = fps[0];
                    const confidence = bestMatch.confidence || 70;

                    insertStmt.run(
                        scanId, result.id,
                        bestMatch.service_name,
                        bestMatch.version_pattern,
                        bestMatch.os_family,
                        bestMatch.cpe,
                        bestMatch.banner_pattern,
                        confidence,
                        bestMatch.id
                    );

                    matches.push({
                        scanResultId: result.id,
                        ip: result.ip_address,
                        port: result.port,
                        service: bestMatch.service_name,
                        version: bestMatch.version_pattern,
                        os: bestMatch.os_family,
                        cpe: bestMatch.cpe,
                        confidence: confidence,
                        allMatches: fps.map(f => ({
                            id: f.id,
                            service: f.service_name,
                            version: f.version_pattern,
                            os: f.os_family,
                            cpe: f.cpe,
                            confidence: f.confidence
                        }))
                    });
                }
            }
        });

        matchAll();
        logger.info(`Fingerprint matching: ${matches.length} matches for scan ${scanId}`);
        return matches;
    }

    // Get fingerprint results for a scan
    static getScanFingerprints(scanId) {
        const db = getDatabase();
        return db.prepare(`
            SELECT sf.*, sr.ip_address, sr.port, sr.protocol, sr.state, sr.risk_level,
                   f.description as fp_description
            FROM scan_fingerprints sf
            JOIN scan_results sr ON sf.scan_result_id = sr.id
            LEFT JOIN fingerprints f ON sf.fingerprint_id = f.id
            WHERE sf.scan_id = ?
            ORDER BY sr.ip_address, sr.port
        `).all(scanId);
    }

    // Get OS detection summary for a scan
    static getScanOSSummary(scanId) {
        const db = getDatabase();
        return db.prepare(`
            SELECT detected_os, COUNT(*) as count
            FROM scan_fingerprints
            WHERE scan_id = ? AND detected_os IS NOT NULL
            GROUP BY detected_os
            ORDER BY count DESC
        `).all(scanId);
    }

    // Get service summary for a scan
    static getScanServiceSummary(scanId) {
        const db = getDatabase();
        return db.prepare(`
            SELECT detected_service, detected_version, COUNT(*) as count
            FROM scan_fingerprints
            WHERE scan_id = ?
            GROUP BY detected_service, detected_version
            ORDER BY count DESC
        `).all(scanId);
    }

    // Create a new fingerprint entry
    static create(data) {
        const db = getDatabase();
        const serviceName = data.serviceName || data.service_name;
        const result = db.prepare(`
            INSERT INTO fingerprints (port, protocol, service_name, version_pattern, banner_pattern, os_family, os_version, cpe, description, confidence, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            data.port, data.protocol || 'tcp', serviceName,
            data.versionPattern || data.version_pattern || null,
            data.bannerPattern || data.banner_pattern || null,
            data.osFamily || data.os_family || null,
            data.osVersion || data.os_version || null,
            data.cpe || null, data.description || null,
            data.confidence || 80,
            data.source || 'custom'
        );
        logger.info(`Fingerprint created: ${serviceName} on port ${data.port} (ID: ${result.lastInsertRowid})`);
        return result.lastInsertRowid;
    }

    // Delete a fingerprint entry
    static delete(id) {
        const db = getDatabase();
        db.prepare('DELETE FROM fingerprints WHERE id = ?').run(id);
        logger.info(`Fingerprint deleted: ID ${id}`);
    }
}

module.exports = FingerprintService;