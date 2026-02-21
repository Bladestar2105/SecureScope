/**
 * Sync Worker - Runs heavy import tasks in a separate process
 * Usage: node syncWorker.js <type> <userId>
 * Types: cve, fingerprints, exploits
 * 
 * Optimized for:
 * - Disk efficiency: CVE sync extracts year-by-year, cleaning as it goes
 * - Memory efficiency: small batches, periodic GC
 * - Crash recovery: checkpoint support
 * - Progress reporting via stdout JSON lines
 */

const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const { execSync } = require('child_process');

const Database = require('better-sqlite3');
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, '..', 'database', 'securescope.db');
const DATA_DIR = path.join(__dirname, '..', 'data');
const CHECKPOINT_DIR = path.join(DATA_DIR, '.checkpoints');

let db;
function getDb() {
    if (!db) {
        db = new Database(DB_PATH);
        db.pragma('journal_mode = WAL');
        db.pragma('foreign_keys = ON');
        db.pragma('synchronous = NORMAL');
        db.pragma('cache_size = -16000');
        db.pragma('temp_store = MEMORY');
        db.pragma('busy_timeout = 30000');
        db.pragma('wal_autocheckpoint = 500');
    }
    return db;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function emit(phase, percent, message, result) {
    const obj = { phase, percent: Math.min(Math.max(percent, 0), 100), message };
    if (result) obj.result = result;
    try { process.stdout.write(JSON.stringify(obj) + '\n'); } catch {}
}

function ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function saveCheckpoint(type, data) {
    ensureDir(CHECKPOINT_DIR);
    fs.writeFileSync(path.join(CHECKPOINT_DIR, `${type}.json`), JSON.stringify(data));
}

function loadCheckpoint(type) {
    const cpFile = path.join(CHECKPOINT_DIR, `${type}.json`);
    try { return fs.existsSync(cpFile) ? JSON.parse(fs.readFileSync(cpFile, 'utf8')) : null; } catch { return null; }
}

function clearCheckpoint(type) {
    const cpFile = path.join(CHECKPOINT_DIR, `${type}.json`);
    try { if (fs.existsSync(cpFile)) fs.unlinkSync(cpFile); } catch {}
}

function gc() { if (global.gc) try { global.gc(); } catch {} }

function execSafe(cmd, options = {}) {
    try {
        return execSync(cmd, { ...options, stdio: 'pipe' });
    } catch (err) {
        const stdout = err.stdout ? err.stdout.toString() : '';
        const stderr = err.stderr ? err.stderr.toString() : '';
        throw new Error(`Command failed: ${cmd}\nSTDOUT: ${stdout}\nSTDERR: ${stderr}\nError: ${err.message}`);
    }
}

// ============================================
// CVE SYNC - Disk-Efficient Year-by-Year Extraction
// ============================================
async function syncCVE(userId) {
    const CVE_DIR = path.join(DATA_DIR, 'cve');
    ensureDir(CVE_DIR);
    const database = getDb();

    // Ensure table + indexes
    database.exec(`
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            state TEXT DEFAULT 'PUBLISHED',
            date_published TEXT, date_updated TEXT,
            title TEXT, description TEXT,
            severity TEXT, cvss_score REAL, cvss_vector TEXT,
            affected_products TEXT, references_json TEXT, source_data_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    try {
        database.exec(`CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity)`);
        database.exec(`CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score)`);
        database.exec(`CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_entries(date_published)`);
    } catch {}

    const countBefore = database.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;
    const logEntry = database.prepare(`
        INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
        VALUES ('cve', 'cvelistV5-github', ?, 'running', ?)
    `).run(countBefore, userId);
    const logId = logEntry.lastInsertRowid;

    try {
        const zipPath = path.join(CVE_DIR, 'cvelistV5-main.zip');
        const extractBase = path.join(CVE_DIR, 'extracted');

        // Step 1: Download zip if not already present
        if (!fs.existsSync(zipPath) || fs.statSync(zipPath).size < 100000) {
            emit('download', 2, 'Lade CVE-Daten von GitHub cvelistV5...');
            const zipUrl = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip';
            emit('download', 5, 'Lade cvelistV5 Repository herunter (ca. 500 MB)...');
            execSafe(`curl -L -f -o "${zipPath}" --connect-timeout 30 --max-time 1200 "${zipUrl}"`, {
                maxBuffer: 10 * 1024 * 1024, timeout: 1260000
            });
            if (!fs.existsSync(zipPath) || fs.statSync(zipPath).size < 100000) {
                throw new Error('Download fehlgeschlagen oder Datei zu klein');
            }
            const zipSize = (fs.statSync(zipPath).size / 1024 / 1024).toFixed(0);
            emit('download', 25, `Download fertig (${zipSize} MB).`);
        } else {
            const zipSize = (fs.statSync(zipPath).size / 1024 / 1024).toFixed(0);
            emit('download', 25, `Vorhandene ZIP-Datei gefunden (${zipSize} MB). Überspringe Download.`);
        }

        // Step 2: List year directories inside the zip without full extraction
        emit('extract', 28, 'Analysiere ZIP-Inhalt...');
        let yearList = [];
        try {
            const zipContents = execSync(`unzip -l "${zipPath}" | grep "cvelistV5-main/cves/" | awk -F'/' '{print $3}' | sort -u | grep -E "^[0-9]{4}$"`, {
                maxBuffer: 50 * 1024 * 1024, timeout: 60000
            }).toString().trim();
            yearList = zipContents.split('\n').filter(y => /^\d{4}$/.test(y)).sort();
        } catch {
            // Fallback: extract everything
            yearList = [];
        }

        if (yearList.length === 0) {
            // Fallback: full extraction
            emit('extract', 30, 'Entpacke vollständig (Fallback)...');
            if (fs.existsSync(extractBase)) execSync(`rm -rf "${extractBase}"`);
            ensureDir(extractBase);
            execSafe(`unzip -q -o "${zipPath}" -d "${extractBase}"`, { maxBuffer: 50 * 1024 * 1024, timeout: 600000 });
            const cvesDir = path.join(extractBase, 'cvelistV5-main', 'cves');
            if (!fs.existsSync(cvesDir)) throw new Error('CVE-Verzeichnis nicht gefunden');
            yearList = fs.readdirSync(cvesDir).filter(d => /^\d{4}$/.test(d)).sort();
        }

        emit('extract', 32, `${yearList.length} Jahre gefunden (${yearList[0]} - ${yearList[yearList.length-1]}). Starte Import...`);

        // Prepare insert
        const insertStmt = database.prepare(`
            INSERT OR REPLACE INTO cve_entries 
            (cve_id, state, date_published, date_updated, title, description, severity, cvss_score, 
             cvss_vector, affected_products, references_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        let totalProcessed = 0, totalAdded = 0, totalErrors = 0;

        const insertBatch = database.transaction((items) => {
            for (const item of items) {
                try {
                    insertStmt.run(item.cveId, item.state, item.datePublished, item.dateUpdated,
                        item.title, item.description, item.severity, item.cvssScore,
                        item.cvssVector, item.affectedProducts, item.referencesJson);
                } catch (err) {
                    totalErrors++;
                    console.error(`Error inserting CVE ${item.cveId}: ${err.message}`);
                }
            }
        });
        const checkpoint = loadCheckpoint('cve');
        let startYearIdx = 0;
        if (checkpoint && checkpoint.lastYearIdx !== undefined) {
            startYearIdx = checkpoint.lastYearIdx + 1;
            totalProcessed = checkpoint.totalProcessed || 0;
            totalAdded = checkpoint.totalAdded || 0;
            emit('extract', 33, `Setze fort ab Jahr ${yearList[startYearIdx] || 'Ende'} (${totalProcessed} bereits verarbeitet)...`);
        }

        // Step 3: Extract and process year by year
        for (let yi = startYearIdx; yi < yearList.length; yi++) {
            const year = yearList[yi];
            const yearExtractDir = path.join(CVE_DIR, 'year_tmp');

            // Clean previous year extraction
            if (fs.existsSync(yearExtractDir)) execSync(`rm -rf "${yearExtractDir}"`);
            ensureDir(yearExtractDir);

            // Extract only this year's files from the zip
            emit('extract', 33 + Math.round((yi / yearList.length) * 5), `Entpacke Jahr ${year}...`);
            try {
                execSafe(`unzip -q -o "${zipPath}" "cvelistV5-main/cves/${year}/*" -d "${yearExtractDir}"`, {
                    maxBuffer: 50 * 1024 * 1024, timeout: 120000
                });
            } catch (e) {
                // Some years might not exist in zip
                totalErrors++;
                emit('extract', 33 + Math.round((yi / yearList.length) * 5), `Warnung: Jahr ${year} konnte nicht entpackt werden: ${e.message}`);
                continue;
            }

            const yearCvesDir = path.join(yearExtractDir, 'cvelistV5-main', 'cves', year);
            if (!fs.existsSync(yearCvesDir)) {
                execSync(`rm -rf "${yearExtractDir}"`);
                continue;
            }

            // Process all JSON files in this year
            let subDirs;
            try {
                subDirs = fs.readdirSync(yearCvesDir).filter(d => {
                    try { return fs.statSync(path.join(yearCvesDir, d)).isDirectory(); } catch { return false; }
                });
            } catch { subDirs = []; }

            let batch = [];
            let yearAdded = 0;
            const BATCH_SIZE = 500;

            for (const sub of subDirs) {
                const subPath = path.join(yearCvesDir, sub);
                let files;
                try { files = fs.readdirSync(subPath).filter(f => f.endsWith('.json')); } catch { continue; }

                for (const file of files) {
                    totalProcessed++;
                    try {
                        const raw = fs.readFileSync(path.join(subPath, file), 'utf8');
                        const cveData = JSON.parse(raw);
                        const parsed = parseCVEv5(cveData);
                        if (parsed) batch.push(parsed);
                    } catch (err) {
                        totalErrors++;
                        console.error(`Error parsing CVE file ${file}: ${err.message}`);
                    }

                    if (batch.length >= BATCH_SIZE) {
                        const before = totalAdded;
                        insertBatch(batch);
                        totalAdded += batch.length;
                        yearAdded += batch.length;
                        batch = [];
                        if (totalProcessed % 5000 === 0) await sleep(20);
                    }
                }
            }

            // Flush remaining
            if (batch.length > 0) {
                insertBatch(batch);
                totalAdded += batch.length;
                yearAdded += batch.length;
                batch = [];
            }

            // Clean up this year's extraction immediately
            execSync(`rm -rf "${yearExtractDir}"`);

            const pct = 38 + Math.round((yi / yearList.length) * 55);
            emit('import', Math.min(pct, 94), `Jahr ${year}: +${yearAdded} | Gesamt: ${totalAdded} importiert / ${totalProcessed} verarbeitet`);

            // Save checkpoint
            saveCheckpoint('cve', { lastYearIdx: yi, totalProcessed, totalAdded, totalErrors });

            await sleep(10);
            gc();
        }

        // Step 4: Cleanup
        emit('cleanup', 95, 'Räume auf...');
        try { execSync(`rm -rf "${path.join(CVE_DIR, 'year_tmp')}"`); } catch {}
        // Delete the zip to free disk space
        try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch {}
        // Delete any leftover extracted dir
        try { if (fs.existsSync(extractBase)) execSync(`rm -rf "${extractBase}"`); } catch {}
        clearCheckpoint('cve');

        const countAfter = database.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;
        database.prepare(`
            UPDATE db_update_log SET entries_added = ?, entries_updated = 0, entries_after = ?,
            status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(totalAdded, countAfter, logId);

        emit('done', 100, `Fertig! ${totalAdded} CVEs importiert. Gesamt: ${countAfter}`, {
            before: countBefore, added: totalAdded, errors: totalErrors, after: countAfter, totalProcessed
        });

    } catch (err) {
        saveCheckpoint('cve', { error: err.message, timestamp: new Date().toISOString() });
        database.prepare(`
            UPDATE db_update_log SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(err.message, logId);
        emit('error', 0, `Fehler: ${err.message}`);
        // Cleanup on error
        try { execSync(`rm -rf "${path.join(CVE_DIR, 'year_tmp')}"`); } catch {}
        try { execSync(`rm -rf "${path.join(CVE_DIR, 'extracted')}"`); } catch {}
        process.exit(1);
    }
}

function parseCVEv5(data) {
    try {
        const cveId = data.cveMetadata?.cveId;
        if (!cveId) return null;
        const state = data.cveMetadata?.state || 'PUBLISHED';
        const datePublished = data.cveMetadata?.datePublished || null;
        const dateUpdated = data.cveMetadata?.dateUpdated || null;
        const cna = data.containers?.cna || {};

        const title = cna.title || (cna.descriptions?.[0]?.value?.substring(0, 200)) || cveId;
        let description = null;
        if (cna.descriptions) {
            const enDesc = cna.descriptions.find(d => d.lang === 'en' || d.lang?.startsWith('en'));
            description = enDesc?.value || cna.descriptions[0]?.value || null;
        }

        let severity = null, cvssScore = null, cvssVector = null;
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
        if (!severity && cvssScore) {
            if (cvssScore >= 9.0) severity = 'critical';
            else if (cvssScore >= 7.0) severity = 'high';
            else if (cvssScore >= 4.0) severity = 'medium';
            else severity = 'low';
        }

        let affectedProducts = null;
        if (cna.affected) {
            affectedProducts = cna.affected.map(a => `${a.vendor || 'unknown'}/${a.product || 'unknown'}`).slice(0, 20).join(', ');
        }

        let referencesJson = null;
        if (cna.references) {
            referencesJson = JSON.stringify(cna.references.slice(0, 10).map(r => ({ url: r.url, name: r.name || null, tags: r.tags || [] })));
        }

        return {
            cveId, state, datePublished, dateUpdated,
            title: title?.substring(0, 500),
            description: description?.substring(0, 5000),
            severity, cvssScore, cvssVector,
            affectedProducts: affectedProducts?.substring(0, 2000),
            referencesJson
        };
    } catch { return null; }
}

// ============================================
// FINGERPRINT SYNC (Nmap)
// ============================================
async function syncFingerprints(userId) {
    const NMAP_DIR = path.join(DATA_DIR, 'nmap');
    ensureDir(NMAP_DIR);
    const database = getDb();

    const countBefore = database.prepare('SELECT COUNT(*) as c FROM fingerprints').get().c;
    const logEntry = database.prepare(`
        INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
        VALUES ('fingerprints', 'nmap-services + nmap-os-db + nmap-service-probes', ?, 'running', ?)
    `).run(countBefore, userId);
    const logId = logEntry.lastInsertRowid;

    try {
        emit('download', 5, 'Lade nmap-services...');
        const svcData = await downloadToString('https://raw.githubusercontent.com/nmap/nmap/master/nmap-services');
        fs.writeFileSync(path.join(NMAP_DIR, 'nmap-services'), svcData);

        emit('download', 20, 'Lade nmap-os-db...');
        const osData = await downloadToString('https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db');
        fs.writeFileSync(path.join(NMAP_DIR, 'nmap-os-db'), osData);

        emit('download', 35, 'Lade nmap-service-probes...');
        const probeData = await downloadToString('https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes');
        fs.writeFileSync(path.join(NMAP_DIR, 'nmap-service-probes'), probeData);

        emit('parse', 45, 'Parse nmap-services...');
        const services = parseNmapServices(svcData);
        emit('parse', 55, 'Parse nmap-os-db...');
        const osFingerprints = parseNmapOsDb(osData);
        emit('parse', 65, 'Parse nmap-service-probes...');
        const serviceProbes = parseNmapServiceProbes(probeData);

        emit('import', 70, `Importiere ${services.length + osFingerprints.length} Einträge + Probes...`);

        let added = 0;
        const BATCH = 1000;

        database.prepare("DELETE FROM fingerprints WHERE source IN ('nmap-services', 'nmap-os-db', 'nmap-service-probes')").run();

        const insertStmt = database.prepare(`
            INSERT INTO fingerprints (port, protocol, service_name, version_pattern, banner_pattern, os_family, os_version, cpe, description, confidence, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (let i = 0; i < services.length; i += BATCH) {
            const batch = services.slice(i, i + BATCH);
            database.transaction((items) => {
                for (const s of items) {
                    insertStmt.run(s.port, s.protocol, s.name, null, null, null, null, null, s.description || s.name, Math.round(s.frequency * 100) || 50, 'nmap-services');
                    added++;
                }
            })(batch);
        }
        emit('import', 80, `nmap-services: ${added} importiert`);

        for (let i = 0; i < osFingerprints.length; i += BATCH) {
            database.transaction((items) => {
                for (const os of items) {
                    insertStmt.run(0, 'tcp', os.name, os.version || null, null, os.osFamily, os.osVersion, os.cpe || null, `OS: ${os.name}`, os.confidence || 70, 'nmap-os-db');
                    added++;
                }
            })(osFingerprints.slice(i, i + BATCH));
        }
        emit('import', 88, `+ nmap-os-db: ${osFingerprints.length} OS-Fingerprints`);

        let probeMatches = [];
        for (const probe of serviceProbes) {
            for (const match of probe.matches) probeMatches.push(match);
        }
        for (let i = 0; i < probeMatches.length; i += BATCH) {
            database.transaction((items) => {
                for (const m of items) {
                    insertStmt.run(m.port || 0, 'tcp', m.service, m.versionPattern || null, m.pattern || null, m.osFamily || null, null, m.cpe || null, m.info || `${m.service} probe`, m.confidence || 75, 'nmap-service-probes');
                    added++;
                }
            })(probeMatches.slice(i, i + BATCH));
        }

        const countAfter = database.prepare('SELECT COUNT(*) as c FROM fingerprints').get().c;
        database.prepare(`
            UPDATE db_update_log SET entries_added = ?, entries_updated = 0, entries_after = ?,
            status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(added, countAfter, logId);

        emit('done', 100, `Fertig! ${added} Fingerprints importiert. Gesamt: ${countAfter}`, {
            before: countBefore, added, after: countAfter,
            sources: { services: services.length, os: osFingerprints.length, probes: probeMatches.length }
        });
    } catch (err) {
        database.prepare(`UPDATE db_update_log SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`).run(err.message, logId);
        emit('error', 0, `Fehler: ${err.message}`);
        process.exit(1);
    }
}

// ============================================
// EXPLOIT SYNC (ExploitDB)
// ============================================
async function syncExploits(userId) {
    const EXPLOITDB_DIR = path.join(DATA_DIR, 'exploitdb');
    ensureDir(DATA_DIR);
    const database = getDb();

    const countBefore = database.prepare('SELECT COUNT(*) as c FROM exploits').get().c;
    const logEntry = database.prepare(`
        INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
        VALUES ('exploits', 'exploit-database/exploitdb (GitLab)', ?, 'running', ?)
    `).run(countBefore, userId);
    const logId = logEntry.lastInsertRowid;

    try {
        const repoExists = fs.existsSync(path.join(EXPLOITDB_DIR, '.git'));

        if (repoExists) {
            emit('download', 5, 'Aktualisiere ExploitDB Repository (git pull)...');
            try {
                execSafe(`cd "${EXPLOITDB_DIR}" && git pull --ff-only`, { maxBuffer: 50 * 1024 * 1024, timeout: 300000 });
            } catch (err) {
                emit('download', 10, `Git pull fehlgeschlagen (${err.message}), versuche Reset...`);
                execSafe(`cd "${EXPLOITDB_DIR}" && git fetch origin && git reset --hard origin/main`, { maxBuffer: 50 * 1024 * 1024, timeout: 300000 });
            }
        } else {
            emit('download', 5, 'Klone ExploitDB Repository (kann mehrere Minuten dauern)...');
            execSafe(`git clone --depth 1 "https://gitlab.com/exploit-database/exploitdb.git" "${EXPLOITDB_DIR}"`, { maxBuffer: 50 * 1024 * 1024, timeout: 600000 });
        }
        emit('download', 30, 'Repository bereit.');

        const csvPath = path.join(EXPLOITDB_DIR, 'files_exploits.csv');
        if (!fs.existsSync(csvPath)) throw new Error('files_exploits.csv nicht gefunden');

        emit('parse', 35, 'Parse files_exploits.csv...');
        const csvData = fs.readFileSync(csvPath, 'utf8');
        const lines = csvData.split('\n');
        emit('parse', 40, `${lines.length} Zeilen gefunden. Importiere...`);

        database.prepare("DELETE FROM exploits WHERE source = 'exploit-db'").run();

        const insertStmt = database.prepare(`
            INSERT INTO exploits (exploit_db_id, cve_id, title, description, platform, exploit_type,
                service_name, service_version_min, service_version_max, port, severity, cvss_score,
                reliability, source, source_url, exploit_code, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, 'exploit-db', ?, ?, ?)
        `);

        let added = 0, errors = 0;
        const BATCH = 1000;
        let batch = [];

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            try {
                const fields = parseCSVLine(line);
                if (fields.length < 9) continue;

                const edbId = fields[0]?.trim();
                const filePath = fields[1]?.trim();
                const title = fields[2]?.trim();
                const datePublished = fields[3]?.trim();
                const author = fields[4]?.trim();
                const platform = fields[5]?.trim();
                const type = fields[6]?.trim();
                const port = fields[7]?.trim();
                const codes = fields[8]?.trim();

                if (!edbId || !title) continue;

                let cveId = null;
                if (codes) { const m = codes.match(/CVE-\d{4}-\d+/); if (m) cveId = m[0]; }

                let severity = 'medium';
                const tl = (type || '').toLowerCase();
                if (tl === 'remote' || tl === 'webapps') severity = 'high';

                let portNum = null;
                if (port && port !== '' && port !== '0') { portNum = parseInt(port, 10); if (isNaN(portNum) || portNum <= 0 || portNum > 65535) portNum = null; }

                const codePath = filePath ? path.join(EXPLOITDB_DIR, filePath) : null;
                const codeExists = codePath && fs.existsSync(codePath);

                batch.push({
                    edbId: `EDB-${edbId}`, cveId, title: title.substring(0, 500),
                    desc: `${title} (Author: ${author || 'unknown'}, Published: ${datePublished || 'unknown'})`,
                    platform: normPlatform(platform), type: tl || 'remote',
                    service: extractService(title), port: portNum, severity,
                    reliability: codeExists ? 'verified' : 'unknown',
                    url: `https://www.exploit-db.com/exploits/${edbId}`,
                    code: codeExists ? codePath : null,
                    verified: codeExists ? 1 : 0
                });
            } catch (err) {
                errors++;
                console.error(`Error parsing exploit CSV line ${i}: ${err.message}`);
            }

            if (batch.length >= BATCH) {
                database.transaction((items) => {
                    for (const e of items) {
                        try {
                            insertStmt.run(e.edbId, e.cveId, e.title, e.desc, e.platform, e.type, e.service, e.port, e.severity, e.reliability, e.url, e.code, e.verified);
                            added++;
                        } catch (err) {
                            errors++;
                            console.error(`Error inserting exploit ${e.edbId}: ${err.message}`);
                        }
                    }
                })(batch);
                batch = [];
                const pct = 40 + Math.round((i / lines.length) * 45);
                emit('import', pct, `Importiert: ${added} / ${i} (${errors} Fehler)`);
            }
        }

        if (batch.length > 0) {
            database.transaction((items) => {
                for (const e of items) {
                    try {
                        insertStmt.run(e.edbId, e.cveId, e.title, e.desc, e.platform, e.type, e.service, e.port, e.severity, e.reliability, e.url, e.code, e.verified);
                        added++;
                    } catch (err) {
                        errors++;
                        console.error(`Error inserting exploit ${e.edbId}: ${err.message}`);
                    }
                }
            })(batch);
        }

        // Shellcodes
        const scPath = path.join(EXPLOITDB_DIR, 'files_shellcodes.csv');
        if (fs.existsSync(scPath)) {
            emit('import', 90, 'Importiere Shellcodes...');
            const scData = fs.readFileSync(scPath, 'utf8');
            const scLines = scData.split('\n');
            let scBatch = [];
            for (let i = 1; i < scLines.length; i++) {
                const line = scLines[i].trim();
                if (!line) continue;
                try {
                    const f = parseCSVLine(line);
                    if (f.length < 5 || !f[0] || !f[2]) continue;
                    const codePath = f[1] ? path.join(EXPLOITDB_DIR, f[1].trim()) : null;
                    scBatch.push({ edbId: `SHELLCODE-${f[0].trim()}`, title: f[2].trim().substring(0, 500), platform: normPlatform(f[5]?.trim()), url: `https://www.exploit-db.com/shellcodes/${f[0].trim()}`, code: codePath && fs.existsSync(codePath) ? codePath : null });
                } catch (err) {
                    errors++;
                    console.error(`Error parsing shellcode CSV line ${i}: ${err.message}`);
                }
            }
            if (scBatch.length > 0) {
                for (let i = 0; i < scBatch.length; i += BATCH) {
                    database.transaction((items) => {
                        for (const s of items) {
                            try {
                                insertStmt.run(s.edbId, null, s.title, `Shellcode: ${s.title}`, s.platform, 'shellcode', null, null, 'medium', 'unknown', s.url, s.code, 0);
                                added++;
                            } catch (err) {
                                errors++;
                                console.error(`Error inserting shellcode ${s.edbId}: ${err.message}`);
                            }
                        }
                    })(scBatch.slice(i, i + BATCH));
                }
            }
        }

        const countAfter = database.prepare('SELECT COUNT(*) as c FROM exploits').get().c;
        database.prepare(`UPDATE db_update_log SET entries_added = ?, entries_updated = 0, entries_after = ?, status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?`).run(added, countAfter, logId);

        emit('done', 100, `Fertig! ${added} Exploits importiert. Gesamt: ${countAfter}`, {
            before: countBefore, added, errors, after: countAfter
        });
    } catch (err) {
        database.prepare(`UPDATE db_update_log SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`).run(err.message, logId);
        emit('error', 0, `Fehler: ${err.message}`);
        process.exit(1);
    }
}

// ============================================
// HELPERS
// ============================================
function downloadToString(url) {
    return new Promise((resolve, reject) => {
        const doReq = (u, redirects) => {
            if (redirects > 5) return reject(new Error('Too many redirects'));
            const proto = u.startsWith('https') ? https : http;
            proto.get(u, { headers: { 'User-Agent': 'SecureScope/1.0' }, timeout: 30000 }, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) return doReq(res.headers.location, redirects + 1);
                if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
                const chunks = [];
                res.on('data', c => chunks.push(c));
                res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
                res.on('error', reject);
            }).on('error', reject);
        };
        doReq(url, 0);
    });
}

function parseCSVLine(line) {
    const fields = []; let cur = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') { if (inQ && i + 1 < line.length && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ; }
        else if (ch === ',' && !inQ) { fields.push(cur); cur = ''; }
        else cur += ch;
    }
    fields.push(cur);
    return fields;
}

function normPlatform(p) {
    if (!p) return 'Multi';
    const l = p.toLowerCase().trim();
    if (l.includes('linux')) return 'Linux';
    if (l.includes('windows')) return 'Windows';
    if (l.includes('osx') || l.includes('macos')) return 'macOS';
    if (l.includes('multiple') || l.includes('multi')) return 'Multi';
    return p.charAt(0).toUpperCase() + p.slice(1).toLowerCase();
}

function extractService(title) {
    const t = title.toLowerCase();
    const map = { 'openssh': 'OpenSSH', 'apache': 'Apache httpd', 'nginx': 'nginx', 'mysql': 'MySQL', 'postgresql': 'PostgreSQL', 'mongodb': 'MongoDB', 'redis': 'Redis', 'ftp': 'FTP', 'samba': 'Samba', 'wordpress': 'WordPress', 'jenkins': 'Jenkins', 'docker': 'Docker', 'tomcat': 'Apache Tomcat', 'iis': 'IIS' };
    for (const [k, v] of Object.entries(map)) { if (t.includes(k)) return v; }
    return null;
}

function parseNmapServices(data) {
    const results = [];
    for (const line of data.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const parts = line.split('\t');
        if (parts.length < 3) continue;
        const name = parts[0].trim();
        const pp = parts[1].trim().split('/');
        if (pp.length !== 2) continue;
        const port = parseInt(pp[0], 10);
        const protocol = pp[1];
        const freq = parseFloat(parts[2]) || 0;
        if (freq < 0.00005 && port > 1024) continue;
        if (port > 65535 || port < 0) continue;
        results.push({ name, port, protocol, frequency: freq, description: parts[3]?.replace(/^#\s*/, '').trim() || name });
    }
    return results;
}

function parseNmapOsDb(data) {
    const results = []; let cur = null;
    for (const line of data.split('\n')) {
        if (line.startsWith('Fingerprint ')) {
            if (cur) results.push(cur);
            cur = { name: line.substring(12).trim(), osFamily: null, osVersion: null, cpe: null, confidence: 80, version: null };
        } else if (line.startsWith('Class ') && cur) {
            const parts = line.substring(6).trim().split('|').map(p => p.trim());
            if (parts.length >= 2) { cur.osFamily = parts[1] || cur.osFamily; if (parts.length >= 3) cur.osVersion = parts[2] || null; }
        } else if (line.startsWith('CPE ') && cur) {
            cur.cpe = cur.cpe ? cur.cpe + '; ' + line.substring(4).trim() : line.substring(4).trim();
        }
    }
    if (cur) results.push(cur);
    return results;
}

function parseNmapServiceProbes(data) {
    const results = []; let probe = null;
    for (const line of data.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        if (line.startsWith('Probe ')) {
            if (probe && probe.matches.length > 0) results.push(probe);
            const m = line.match(/^Probe\s+(TCP|UDP)\s+(\S+)/);
            probe = { protocol: m ? m[1].toLowerCase() : 'tcp', name: m ? m[2] : 'unknown', matches: [], ports: [] };
        } else if (line.startsWith('ports ') && probe) {
            probe.ports = line.substring(6).trim().split(',').map(p => { p = p.trim(); if (p.includes('-')) { const [s] = p.split('-').map(Number); return s; } return parseInt(p, 10); }).filter(p => !isNaN(p));
        } else if ((line.startsWith('match ') || line.startsWith('softmatch ')) && probe) {
            const isSoft = line.startsWith('softmatch');
            const ml = isSoft ? line.replace(/^softmatch/, 'match') : line;
            try {
                const sm = ml.match(/^match\s+(\S+)\s+m([|/%=])(.+?)\2([si]*)\s*(.*)/);
                if (!sm) continue;
                const service = sm[1], pattern = sm[3].substring(0, 200), meta = sm[5] || '';
                let vp = null, info = null, osF = null, cpe = null;
                const vm = meta.match(/v\/([^/]*)\//); if (vm) vp = vm[1].replace(/\$\d/g, '*');
                const pm = meta.match(/p\/([^/]*)\//); if (pm) info = pm[1].replace(/\$\d/g, '*');
                const om = meta.match(/o\/([^/]*)\//); if (om) osF = om[1].replace(/\$\d/g, '*');
                const cm = meta.match(/cpe:\/([^\s/]+(?:\/[^\s/]*)*)/); if (cm) cpe = 'cpe:/' + cm[1];
                probe.matches.push({ service, pattern: pattern.substring(0, 200), versionPattern: vp?.substring(0, 100), info: info?.substring(0, 200), osFamily: osF?.substring(0, 100), cpe: cpe?.substring(0, 200), port: probe.ports[0] || 0, confidence: isSoft ? 60 : 80 });
            } catch {}
        }
    }
    if (probe && probe.matches.length > 0) results.push(probe);
    return results;
}

// ============================================
// MAIN
// ============================================
const type = process.argv[2];
const userId = parseInt(process.argv[3]) || 1;

if (!type) { console.error('Usage: node syncWorker.js <cve|fingerprints|exploits> <userId>'); process.exit(1); }

(async () => {
    try {
        if (type === 'cve') await syncCVE(userId);
        else if (type === 'fingerprints') await syncFingerprints(userId);
        else if (type === 'exploits') await syncExploits(userId);
        else { console.error(`Unknown type: ${type}`); process.exit(1); }
    } catch (err) {
        emit('error', 0, `Worker-Fehler: ${err.message}`);
        process.exit(1);
    } finally {
        if (db) db.close();
    }
})();