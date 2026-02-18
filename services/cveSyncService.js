const { getDatabase } = require('../config/database');
const logger = require('./logger');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CVE_DIR = path.join(DATA_DIR, 'cve');

class CVESyncService {

    static progressCallbacks = new Map();

    static ensureDirs() {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        if (!fs.existsSync(CVE_DIR)) fs.mkdirSync(CVE_DIR, { recursive: true });
    }

    static onProgress(id, cb) { this.progressCallbacks.set(id, cb); }
    static offProgress(id) { this.progressCallbacks.delete(id); }
    static emitProgress(phase, pct, msg) {
        for (const cb of this.progressCallbacks.values()) {
            try { cb({ phase, percent: pct, message: msg }); } catch (e) {}
        }
    }

    /**
     * Download a file from URL with progress tracking
     */
    static downloadFile(url, destPath) {
        return new Promise((resolve, reject) => {
            const proto = url.startsWith('https') ? https : http;
            const request = (reqUrl) => {
                proto.get(reqUrl, { headers: { 'User-Agent': 'SecureScope/1.0' } }, (res) => {
                    // Handle redirects
                    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                        return request(res.headers.location);
                    }
                    if (res.statusCode !== 200) {
                        return reject(new Error(`HTTP ${res.statusCode} for ${reqUrl}`));
                    }
                    const totalBytes = parseInt(res.headers['content-length'] || '0', 10);
                    let downloaded = 0;
                    const file = fs.createWriteStream(destPath);
                    res.on('data', (chunk) => {
                        downloaded += chunk.length;
                        if (totalBytes > 0) {
                            const pct = Math.round((downloaded / totalBytes) * 100);
                            this.emitProgress('download', pct, `Download: ${(downloaded / 1024 / 1024).toFixed(1)} MB / ${(totalBytes / 1024 / 1024).toFixed(1)} MB`);
                        } else {
                            this.emitProgress('download', -1, `Download: ${(downloaded / 1024 / 1024).toFixed(1)} MB`);
                        }
                    });
                    res.pipe(file);
                    file.on('finish', () => { file.close(); resolve(destPath); });
                    file.on('error', (err) => { fs.unlink(destPath, () => {}); reject(err); });
                }).on('error', reject);
            };
            request(url);
        });
    }

    /**
     * Download file using wget/curl (more reliable for large files with redirects)
     */
    static async downloadWithCurl(url, destPath) {
        return new Promise((resolve, reject) => {
            const cmd = `curl -L -f -o "${destPath}" --progress-bar --max-time 600 --connect-timeout 30 "${url}"`;
            this.emitProgress('download', 0, `Starte Download von ${url.split('/').pop()}...`);
            exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
                if (err) {
                    // Try wget as fallback
                    const wgetCmd = `wget -q -O "${destPath}" --timeout=30 "${url}"`;
                    exec(wgetCmd, { maxBuffer: 10 * 1024 * 1024 }, (err2) => {
                        if (err2) return reject(new Error(`Download fehlgeschlagen: ${err.message}`));
                        resolve(destPath);
                    });
                    return;
                }
                resolve(destPath);
            });
        });
    }

    /**
     * Sync CVE data from the cvelistV5 GitHub repository
     * Uses the GitHub API to get recent CVEs efficiently
     */
    static async syncFromGitHub(userId) {
        this.ensureDirs();
        const db = getDatabase();
        const countBefore = db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;

        // Log start
        const logEntry = db.prepare(`
            INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
            VALUES ('cve', 'cvelistV5-github', ?, 'running', ?)
        `).run(countBefore, userId);
        const logId = logEntry.lastInsertRowid;

        try {
            this.emitProgress('init', 0, 'Lade CVE-Daten von GitHub cvelistV5...');

            // Strategy: Download the main.zip from GitHub (contains all CVEs in JSON)
            // This is the official recommended approach from cve.org
            const zipUrl = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip';
            const zipPath = path.join(CVE_DIR, 'cvelistV5-main.zip');

            this.emitProgress('download', 5, 'Lade cvelistV5 Repository herunter (kann mehrere Minuten dauern)...');
            await this.downloadWithCurl(zipUrl, zipPath);

            if (!fs.existsSync(zipPath) || fs.statSync(zipPath).size < 1000) {
                throw new Error('Download fehlgeschlagen oder Datei zu klein');
            }

            this.emitProgress('extract', 30, 'Entpacke CVE-Archiv...');

            // Extract the zip
            const extractDir = path.join(CVE_DIR, 'extracted');
            if (fs.existsSync(extractDir)) {
                execSync(`rm -rf "${extractDir}"`);
            }
            fs.mkdirSync(extractDir, { recursive: true });
            execSync(`unzip -q -o "${zipPath}" -d "${extractDir}"`, { maxBuffer: 50 * 1024 * 1024 });

            // Find the cves directory inside the extracted archive
            const mainDir = path.join(extractDir, 'cvelistV5-main');
            const cvesDir = path.join(mainDir, 'cves');

            if (!fs.existsSync(cvesDir)) {
                throw new Error('CVE-Verzeichnis nicht gefunden im Archiv');
            }

            this.emitProgress('parse', 40, 'Zähle CVE-Einträge...');

            // Get all year directories
            const yearDirs = fs.readdirSync(cvesDir).filter(d => /^\d{4}$/.test(d)).sort();
            let totalFiles = 0;
            let processed = 0;
            let added = 0;
            let updated = 0;
            let errors = 0;

            // Count total files using find (much faster than JS iteration)
            try {
                const countOutput = execSync(`find "${cvesDir}" -name "*.json" -type f | wc -l`, { maxBuffer: 10 * 1024 * 1024 }).toString().trim();
                totalFiles = parseInt(countOutput, 10) || 0;
            } catch (e) {
                totalFiles = 280000; // Approximate
            }

            this.emitProgress('parse', 45, `~${totalFiles} CVE-Dateien gefunden. Importiere...`);

            // Prepare statements
            const insertStmt = db.prepare(`
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, state, date_published, date_updated, title, description, severity, cvss_score, 
                 cvss_vector, affected_products, references_json, source_data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            // Process in small batches to avoid memory issues
            const BATCH_SIZE = 1000;
            let batch = [];

            const processBatch = db.transaction((items) => {
                for (const item of items) {
                    try {
                        insertStmt.run(
                            item.cveId, item.state, item.datePublished, item.dateUpdated,
                            item.title, item.description, item.severity, item.cvssScore,
                            item.cvssVector, item.affectedProducts, item.referencesJson, null
                        );
                        added++;
                    } catch (e) {
                        errors++;
                    }
                }
            });

            // Process each year directory - memory efficient approach
            for (const year of yearDirs) {
                const yearPath = path.join(cvesDir, year);
                let subDirs;
                try { subDirs = fs.readdirSync(yearPath).filter(d => { try { return fs.statSync(path.join(yearPath, d)).isDirectory(); } catch { return false; } }); } catch { continue; }

                for (const sub of subDirs) {
                    const subPath = path.join(yearPath, sub);
                    let files;
                    try { files = fs.readdirSync(subPath).filter(f => f.endsWith('.json')); } catch { continue; }

                    for (const file of files) {
                        processed++;
                        try {
                            const filePath = path.join(subPath, file);
                            const raw = fs.readFileSync(filePath, 'utf8');
                            const cveData = JSON.parse(raw);
                            const parsed = this.parseCVEv5(cveData);
                            if (parsed) {
                                batch.push(parsed);
                                if (batch.length >= BATCH_SIZE) {
                                    processBatch(batch);
                                    batch = [];
                                    // Force garbage collection hint
                                    if (processed % 10000 === 0) {
                                        const pct = 45 + Math.round((processed / totalFiles) * 50);
                                        this.emitProgress('import', pct, `Importiert: ${added} / ${processed} verarbeitet (${errors} Fehler)`);
                                    }
                                }
                            }
                        } catch (e) {
                            errors++;
                        }
                    }
                }
                // Emit progress per year
                const pct = 45 + Math.round((processed / totalFiles) * 50);
                this.emitProgress('import', pct, `Jahr ${year}: ${added} importiert / ${processed} verarbeitet`);
            }

            // Process remaining batch
            if (batch.length > 0) {
                processBatch(batch);
            }

            this.emitProgress('cleanup', 96, 'Räume auf...');

            // Cleanup extracted files (keep zip for delta updates)
            execSync(`rm -rf "${extractDir}"`);

            const countAfter = db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;

            // Update log
            db.prepare(`
                UPDATE db_update_log SET entries_added = ?, entries_updated = ?, entries_after = ?, 
                status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(added, updated, countAfter, logId);

            this.emitProgress('done', 100, `Fertig! ${added} neue, ${updated} aktualisierte CVEs. Gesamt: ${countAfter}`);

            logger.info(`CVE sync completed: ${added} added, ${updated} updated, ${errors} errors (${countBefore} → ${countAfter})`);

            return {
                success: true,
                message: `CVE-Datenbank aktualisiert: ${added} neue, ${updated} aktualisierte Einträge`,
                stats: { before: countBefore, added, updated, errors, after: countAfter, totalProcessed: processed }
            };

        } catch (err) {
            db.prepare(`
                UPDATE db_update_log SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(err.message, logId);
            this.emitProgress('error', 0, `Fehler: ${err.message}`);
            logger.error('CVE sync error:', err);
            throw err;
        }
    }

    /**
     * Parse a CVE v5 JSON record into our database format
     */
    static parseCVEv5(data) {
        try {
            const cveId = data.cveMetadata?.cveId;
            if (!cveId) return null;

            const state = data.cveMetadata?.state || 'PUBLISHED';
            const datePublished = data.cveMetadata?.datePublished || null;
            const dateUpdated = data.cveMetadata?.dateUpdated || null;

            const cna = data.containers?.cna || {};

            // Title
            const title = cna.title || (cna.descriptions?.[0]?.value?.substring(0, 200)) || cveId;

            // Description (English preferred)
            let description = null;
            if (cna.descriptions) {
                const enDesc = cna.descriptions.find(d => d.lang === 'en' || d.lang?.startsWith('en'));
                description = enDesc?.value || cna.descriptions[0]?.value || null;
            }

            // CVSS / Severity
            let severity = null;
            let cvssScore = null;
            let cvssVector = null;

            if (cna.metrics) {
                for (const metric of cna.metrics) {
                    const cvss = metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV4_0 || metric.cvssV2_0;
                    if (cvss) {
                        cvssScore = cvss.baseScore || null;
                        cvssVector = cvss.vectorString || null;
                        severity = cvss.baseSeverity?.toLowerCase() || null;
                        break;
                    }
                }
            }

            // Derive severity from score if not set
            if (!severity && cvssScore) {
                if (cvssScore >= 9.0) severity = 'critical';
                else if (cvssScore >= 7.0) severity = 'high';
                else if (cvssScore >= 4.0) severity = 'medium';
                else severity = 'low';
            }

            // Affected products
            let affectedProducts = null;
            if (cna.affected) {
                const products = cna.affected.map(a => {
                    const vendor = a.vendor || 'unknown';
                    const product = a.product || 'unknown';
                    return `${vendor}/${product}`;
                }).slice(0, 20);
                affectedProducts = products.join(', ');
            }

            // References
            let referencesJson = null;
            if (cna.references) {
                const refs = cna.references.slice(0, 10).map(r => ({
                    url: r.url,
                    name: r.name || null,
                    tags: r.tags || []
                }));
                referencesJson = JSON.stringify(refs);
            }

            return {
                cveId,
                state,
                datePublished,
                dateUpdated,
                title: title?.substring(0, 500),
                description: description?.substring(0, 5000),
                severity,
                cvssScore,
                cvssVector,
                affectedProducts: affectedProducts?.substring(0, 2000),
                referencesJson,
                sourceJson: null // Don't store full source to save space
            };
        } catch (e) {
            return null;
        }
    }

    /**
     * Get CVE stats
     */
    static getStats() {
        const db = getDatabase();
        try {
            const total = db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;
            const bySeverity = db.prepare('SELECT severity, COUNT(*) as count FROM cve_entries WHERE severity IS NOT NULL GROUP BY severity ORDER BY count DESC').all();
            const byYear = db.prepare("SELECT substr(cve_id, 5, 4) as year, COUNT(*) as count FROM cve_entries GROUP BY year ORDER BY year DESC").all();
            const lastSync = db.prepare("SELECT completed_at FROM db_update_log WHERE database_type = 'cve' AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").get();
            const recentCVEs = db.prepare('SELECT cve_id, title, severity, cvss_score, date_published FROM cve_entries WHERE state = ? ORDER BY date_published DESC LIMIT 10').all('PUBLISHED');

            return { total, bySeverity, byYear, lastSync: lastSync?.completed_at, recentCVEs };
        } catch (e) {
            return { total: 0, bySeverity: [], byYear: [], lastSync: null, recentCVEs: [] };
        }
    }

    /**
     * Search CVEs
     */
    static search(filters = {}) {
        const db = getDatabase();
        let query = 'SELECT * FROM cve_entries WHERE 1=1';
        const params = [];

        if (filters.severity) {
            query += ' AND severity = ?';
            params.push(filters.severity);
        }
        if (filters.year) {
            query += ' AND cve_id LIKE ?';
            params.push(`CVE-${filters.year}-%`);
        }
        if (filters.search) {
            query += ' AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ? OR affected_products LIKE ?)';
            const term = `%${filters.search}%`;
            params.push(term, term, term, term);
        }
        if (filters.state) {
            query += ' AND state = ?';
            params.push(filters.state);
        }

        query += ' ORDER BY date_published DESC NULLS LAST, cve_id DESC';

        const page = filters.page || 1;
        const limit = filters.limit || 50;
        const offset = (page - 1) * limit;

        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as count');
        const total = db.prepare(countQuery).get(...params);

        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const results = db.prepare(query).all(...params);

        return {
            cves: results,
            pagination: { page, limit, total: total.count, totalPages: Math.ceil(total.count / limit) }
        };
    }
}

module.exports = CVESyncService;