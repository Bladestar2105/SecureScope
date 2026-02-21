const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { getDatabase } = require('../config/database');
const logger = require('../services/logger');
const CVESyncService = require('../services/cveSyncService');
const ExploitDbSyncService = require('../services/exploitDbSyncService');
const { spawn } = require('child_process');
const path = require('path');

// Active sync operations tracking
const activeSyncs = new Map();
// SSE clients per sync type
const sseClients = new Map(); // type -> Set of res objects

/**
 * Spawn a worker process for heavy sync tasks.
 * The worker communicates progress via stdout JSON lines.
 * This keeps the main server process responsive and crash-safe.
 */
function spawnSyncWorker(type, userId) {
    const workerPath = path.join(__dirname, '..', 'services', 'syncWorker.js');
    const child = spawn('node', ['--max-old-space-size=1024', workerPath, type, String(userId)], {
        cwd: path.join(__dirname, '..'),
        env: { ...process.env, DATABASE_PATH: process.env.DATABASE_PATH || path.join(__dirname, '..', 'database', 'securescope.db') },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    activeSyncs.set(type, { status: 'running', startedAt: new Date().toISOString(), pid: child.pid });

    let buffer = '';
    child.stdout.on('data', (data) => {
        buffer += data.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete line
        for (const line of lines) {
            if (!line.trim()) continue;
            try {
                const msg = JSON.parse(line);
                // Broadcast to SSE clients
                broadcastProgress(type, msg);
                // Update active sync status
                if (msg.phase === 'done' || msg.phase === 'error') {
                    activeSyncs.delete(type);
                }
            } catch (e) {
                logger.debug(`Worker ${type} non-JSON output: ${line}`);
            }
        }
    });

    child.stderr.on('data', (data) => {
        const errMsg = data.toString().trim();
        if (errMsg) logger.warn(`Worker ${type} stderr: ${errMsg}`);
    });

    child.on('close', (code) => {
        activeSyncs.delete(type);
        if (code !== 0) {
            logger.error(`Worker ${type} exited with code ${code}`);
            broadcastProgress(type, { phase: 'error', percent: 0, message: `Worker-Prozess beendet (Code ${code}). Bitte erneut versuchen.` });
        }
        // Flush remaining buffer
        if (buffer.trim()) {
            try {
                const msg = JSON.parse(buffer.trim());
                broadcastProgress(type, msg);
            } catch {}
        }
    });

    child.on('error', (err) => {
        activeSyncs.delete(type);
        logger.error(`Worker ${type} spawn error:`, err);
        broadcastProgress(type, { phase: 'error', percent: 0, message: `Worker konnte nicht gestartet werden: ${err.message}` });
    });

    return child;
}

function broadcastProgress(type, data) {
    const clients = sseClients.get(type);
    if (!clients) return;
    const msg = `data: ${JSON.stringify(data)}\n\n`;
    for (const res of clients) {
        try { res.write(msg); } catch {}
    }
    // Close SSE connections on done/error
    if (data.phase === 'done' || data.phase === 'error') {
        for (const res of clients) {
            try { res.end(); } catch {}
        }
        clients.clear();
    }
}

// ============================================
// SSE Progress endpoint
// ============================================
router.get('/progress/:type', requireAuth, (req, res) => {
    const type = req.params.type;
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });

    // Register this SSE client
    if (!sseClients.has(type)) sseClients.set(type, new Set());
    sseClients.get(type).add(res);

    // Send initial status
    res.write(`data: ${JSON.stringify({ phase: 'connected', percent: 0, message: 'Verbunden. Warte auf Sync-Start...' })}\n\n`);

    req.on('close', () => {
        const clients = sseClients.get(type);
        if (clients) clients.delete(res);
    });
});

// ============================================
// Get update history for all databases
// ============================================
router.get('/history', requireAuth, (req, res) => {
    try {
        const db = getDatabase();
        const type = req.query.type;
        let query = 'SELECT * FROM db_update_log';
        const params = [];
        if (type) { query += ' WHERE database_type = ?'; params.push(type); }
        query += ' ORDER BY started_at DESC LIMIT 50';
        const logs = db.prepare(query).all(...params);
        res.json({ logs });
    } catch (err) {
        logger.error('Error fetching update history:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Update-Historie' });
    }
});

// ============================================
// Get database statistics
// ============================================
router.get('/stats', requireAuth, async (req, res) => {
    try {
        const db = getDatabase();
        const stats = {
            fingerprints: {
                total: db.prepare('SELECT COUNT(*) as c FROM fingerprints').get().c,
                bySource: db.prepare('SELECT source, COUNT(*) as count FROM fingerprints GROUP BY source').all(),
                lastUpdate: db.prepare("SELECT MAX(updated_at) as last FROM fingerprints").get().last,
                lastSync: db.prepare("SELECT completed_at FROM db_update_log WHERE database_type = 'fingerprints' AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").get()?.completed_at
            },
            exploits: {
                total: db.prepare('SELECT COUNT(*) as c FROM exploits').get().c,
                bySource: db.prepare('SELECT source, COUNT(*) as count FROM exploits GROUP BY source').all(),
                bySeverity: db.prepare('SELECT severity, COUNT(*) as count FROM exploits GROUP BY severity').all(),
                lastUpdate: db.prepare("SELECT MAX(updated_at) as last FROM exploits").get().last,
                lastSync: db.prepare("SELECT completed_at FROM db_update_log WHERE database_type = 'exploits' AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").get()?.completed_at,
                repoStats: await ExploitDbSyncService.getRepoStats()
            },
            cve: {
                total: db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c,
                bySeverity: db.prepare('SELECT severity, COUNT(*) as count FROM cve_entries WHERE severity IS NOT NULL GROUP BY severity').all(),
                lastSync: db.prepare("SELECT completed_at FROM db_update_log WHERE database_type = 'cve' AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").get()?.completed_at
            },
            vulnerabilities: {
                total: db.prepare('SELECT COUNT(*) as c FROM vulnerabilities').get().c,
                bySeverity: db.prepare('SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity').all(),
                lastUpdate: db.prepare("SELECT MAX(created_at) as last FROM vulnerabilities").get().last
            },
            attackChains: {
                total: db.prepare('SELECT COUNT(*) as c FROM attack_chains').get().c,
                enabled: db.prepare('SELECT COUNT(*) as c FROM attack_chains WHERE enabled = 1').get().c,
                executions: db.prepare('SELECT COUNT(*) as c FROM attack_chain_executions').get().c
            },
            audits: {
                total: db.prepare('SELECT COUNT(*) as c FROM security_audits').get().c,
                avgScore: db.prepare('SELECT AVG(overall_score) as avg FROM security_audits').get().avg
            },
            credentials: {
                total: db.prepare('SELECT COUNT(*) as c FROM credentials').get().c,
                valid: db.prepare('SELECT COUNT(*) as c FROM credentials WHERE is_valid = 1').get().c
            }
        };

        // Add active sync status
        stats.activeSyncs = {};
        for (const [key, val] of activeSyncs.entries()) {
            stats.activeSyncs[key] = val;
        }

        res.json(stats);
    } catch (err) {
        logger.error('Error fetching DB stats:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Statistiken' });
    }
});

// ============================================
// CVE Sync (from cvelistV5 GitHub) - runs in worker process
// ============================================
router.post('/sync/cve', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    if (activeSyncs.has('cve')) {
        return res.status(409).json({ error: 'CVE-Sync läuft bereits' });
    }
    try {
        spawnSyncWorker('cve', req.session.userId);
        res.json({ success: true, message: 'CVE-Sync gestartet (Worker-Prozess). Fortschritt über SSE verfügbar.', async: true });
    } catch (err) {
        activeSyncs.delete('cve');
        logger.error('Error starting CVE sync worker:', err);
        res.status(500).json({ error: 'Fehler beim Starten des CVE-Syncs' });
    }
});

// Get CVE stats
router.get('/cve/stats', requireAuth, (req, res) => {
    try {
        const stats = CVESyncService.getStats();
        res.json(stats);
    } catch (err) {
        logger.error('Error fetching CVE stats:', err);
        res.status(500).json({ error: 'Fehler beim Laden der CVE-Statistiken' });
    }
});

// Search CVEs
router.get('/cve/search', requireAuth, (req, res) => {
    try {
        const filters = {
            severity: req.query.severity,
            year: req.query.year,
            search: req.query.search,
            state: req.query.state,
            page: parseInt(req.query.page) || 1,
            limit: parseInt(req.query.limit) || 50
        };
        const result = CVESyncService.search(filters);
        res.json(result);
    } catch (err) {
        logger.error('Error searching CVEs:', err);
        res.status(500).json({ error: 'Fehler bei der CVE-Suche' });
    }
});

// ============================================
// Fingerprint Sync (from Nmap GitHub) - runs in worker process
// ============================================
router.post('/sync/fingerprints', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    if (activeSyncs.has('fingerprints')) {
        return res.status(409).json({ error: 'Fingerprint-Sync läuft bereits' });
    }
    try {
        spawnSyncWorker('fingerprints', req.session.userId);
        res.json({ success: true, message: 'Fingerprint-Sync gestartet (Worker-Prozess). Fortschritt über SSE verfügbar.', async: true });
    } catch (err) {
        activeSyncs.delete('fingerprints');
        logger.error('Error starting fingerprint sync worker:', err);
        res.status(500).json({ error: 'Fehler beim Starten des Fingerprint-Syncs' });
    }
});

// ============================================
// Exploit Sync (from ExploitDB GitLab) - runs in worker process
// ============================================
router.post('/sync/exploits', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    if (activeSyncs.has('exploits')) {
        return res.status(409).json({ error: 'Exploit-Sync läuft bereits' });
    }
    try {
        spawnSyncWorker('exploits', req.session.userId);
        res.json({ success: true, message: 'Exploit-Sync gestartet (Worker-Prozess). Fortschritt über SSE verfügbar.', async: true });
    } catch (err) {
        activeSyncs.delete('exploits');
        logger.error('Error starting exploit sync worker:', err);
        res.status(500).json({ error: 'Fehler beim Starten des Exploit-Syncs' });
    }
});

// ============================================
// GHDB Sync - runs in worker process
// ============================================
router.post('/sync/ghdb', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    if (activeSyncs.has('ghdb')) {
        return res.status(409).json({ error: 'GHDB-Sync läuft bereits' });
    }
    try {
        spawnSyncWorker('ghdb', req.session.userId);
        res.json({ success: true, message: 'GHDB-Sync gestartet. Fortschritt über SSE verfügbar.', async: true });
    } catch (err) {
        activeSyncs.delete('ghdb');
        logger.error('Error starting GHDB sync worker:', err);
        res.status(500).json({ error: 'Fehler beim Starten des GHDB-Syncs' });
    }
});

// ============================================
// Metasploit Sync - runs in worker process
// ============================================
router.post('/sync/metasploit', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    if (activeSyncs.has('metasploit')) {
        return res.status(409).json({ error: 'Metasploit-Sync läuft bereits' });
    }
    try {
        spawnSyncWorker('metasploit', req.session.userId);
        res.json({ success: true, message: 'Metasploit-Sync gestartet. Fortschritt über SSE verfügbar.', async: true });
    } catch (err) {
        activeSyncs.delete('metasploit');
        logger.error('Error starting Metasploit sync worker:', err);
        res.status(500).json({ error: 'Fehler beim Starten des Metasploit-Syncs' });
    }
});

// Get exploit code
router.get('/exploits/code/:id', requireAuth, (req, res) => {
    try {
        const code = ExploitDbSyncService.getExploitCode(parseInt(req.params.id));
        if (!code) {
            return res.status(404).json({ error: 'Exploit-Code nicht gefunden. Bitte zuerst ExploitDB synchronisieren.' });
        }
        res.json(code);
    } catch (err) {
        logger.error('Error fetching exploit code:', err);
        res.status(500).json({ error: 'Fehler beim Laden des Exploit-Codes' });
    }
});

// Get ExploitDB repo stats
router.get('/exploits/repo-stats', requireAuth, async (req, res) => {
    try {
        const stats = await ExploitDbSyncService.getRepoStats();
        res.json(stats);
    } catch (err) {
        logger.error('Error fetching repo stats:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Repo-Statistiken' });
    }
});

// ============================================
// Vulnerability Sync (kept for backward compat)
// ============================================
router.post('/sync/vulnerabilities', requireAuth, requirePermission('vulnerabilities:edit'), async (req, res) => {
    try {
        const db = getDatabase();
        const countBefore = db.prepare('SELECT COUNT(*) as c FROM vulnerabilities').get().c;

        const logEntry = db.prepare(`
            INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
            VALUES ('vulnerabilities', 'nvd-cve-feed', ?, 'running', ?)
        `).run(countBefore, req.session.userId);
        const logId = logEntry.lastInsertRowid;

        // Import from cve_entries into vulnerabilities if CVE data is available
        const cveCount = db.prepare('SELECT COUNT(*) as c FROM cve_entries').get().c;
        let added = 0;

        if (cveCount > 0) {
            // Import high/critical CVEs that have CVSS scores into vulnerabilities
            const cves = db.prepare(`
                SELECT * FROM cve_entries 
                WHERE severity IN ('critical', 'high') AND cvss_score IS NOT NULL
                AND cve_id NOT IN (SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL)
                ORDER BY cvss_score DESC LIMIT 500
            `).all();

            const insertStmt = db.prepare(`
                INSERT INTO vulnerabilities (cve_id, port, protocol, service, severity, title, description, remediation, cvss_score)
                VALUES (?, ?, 'tcp', ?, ?, ?, ?, ?, ?)
            `);

            const importAll = db.transaction(() => {
                for (const cve of cves) {
                    insertStmt.run(
                        cve.cve_id, null, null,
                        cve.severity, cve.title || cve.cve_id,
                        cve.description || 'Keine Beschreibung verfügbar',
                        'Bitte prüfen Sie die CVE-Details und wenden Sie verfügbare Patches an.',
                        cve.cvss_score
                    );
                    added++;
                }
            });
            importAll();
        }

        const countAfter = db.prepare('SELECT COUNT(*) as c FROM vulnerabilities').get().c;
        db.prepare(`UPDATE db_update_log SET entries_added = ?, entries_after = ?, status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?`).run(added, countAfter, logId);

        res.json({
            success: true,
            message: `Schwachstellen-Datenbank aktualisiert: ${added} neue Einträge`,
            stats: { before: countBefore, added, after: countAfter }
        });
    } catch (err) {
        logger.error('Error syncing vulnerability DB:', err);
        res.status(500).json({ error: 'Fehler beim Aktualisieren der Schwachstellen-Datenbank' });
    }
});

// ============================================
// Bulk import endpoints (kept for backward compat)
// ============================================
router.post('/import/fingerprints', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const { fingerprints } = req.body;
        if (!Array.isArray(fingerprints) || fingerprints.length === 0) {
            return res.status(400).json({ error: 'Keine Fingerprints zum Importieren' });
        }
        const db = getDatabase();
        const stmt = db.prepare(`INSERT INTO fingerprints (port, protocol, service_name, version_pattern, banner_pattern, os_family, cpe, description, confidence, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        let added = 0;
        const importAll = db.transaction(() => {
            for (const fp of fingerprints) {
                if (fp.port && fp.serviceName) {
                    stmt.run(fp.port, fp.protocol || 'tcp', fp.serviceName, fp.versionPattern || null, fp.bannerPattern || null, fp.osFamily || null, fp.cpe || null, fp.description || null, fp.confidence || 75, 'import');
                    added++;
                }
            }
        });
        importAll();
        res.json({ success: true, message: `${added} Fingerprints importiert`, added });
    } catch (err) {
        logger.error('Error importing fingerprints:', err);
        res.status(500).json({ error: 'Fehler beim Importieren' });
    }
});

router.post('/import/exploits', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const { exploits } = req.body;
        if (!Array.isArray(exploits) || exploits.length === 0) {
            return res.status(400).json({ error: 'Keine Exploits zum Importieren' });
        }
        const db = getDatabase();
        const stmt = db.prepare(`INSERT INTO exploits (exploit_db_id, cve_id, title, description, platform, exploit_type, service_name, service_version_min, service_version_max, port, severity, cvss_score, reliability, source, source_url, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        let added = 0;
        const importAll = db.transaction(() => {
            for (const e of exploits) {
                if (e.title) {
                    stmt.run(e.exploitDbId || null, e.cveId || null, e.title, e.description || null, e.platform || 'Multi', e.exploitType || 'remote', e.serviceName || null, e.serviceVersionMin || null, e.serviceVersionMax || null, e.port || null, e.severity || 'high', e.cvssScore || null, e.reliability || 'unknown', e.source || 'import', e.sourceUrl || null, e.verified ? 1 : 0);
                    added++;
                }
            }
        });
        importAll();
        res.json({ success: true, message: `${added} Exploits importiert`, added });
    } catch (err) {
        logger.error('Error importing exploits:', err);
        res.status(500).json({ error: 'Fehler beim Importieren' });
    }
});

// Get sync status
router.get('/sync/status', requireAuth, (req, res) => {
    const status = {};
    for (const [key, val] of activeSyncs.entries()) {
        status[key] = val;
    }
    res.json({ activeSyncs: status });
});

module.exports = router;