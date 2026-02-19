const { getDatabase } = require('../config/database');
const logger = require('./logger');
const https = require('https');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const NMAP_DIR = path.join(DATA_DIR, 'nmap');

const NMAP_SOURCES = {
    services: 'https://raw.githubusercontent.com/nmap/nmap/master/nmap-services',
    osDb: 'https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db',
    serviceProbes: 'https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes'
};

class NmapSyncService {

    static progressCallbacks = new Map();

    static ensureDirs() {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        if (!fs.existsSync(NMAP_DIR)) fs.mkdirSync(NMAP_DIR, { recursive: true });
    }

    static onProgress(id, cb) { this.progressCallbacks.set(id, cb); }
    static offProgress(id) { this.progressCallbacks.delete(id); }
    static emitProgress(phase, pct, msg) {
        for (const cb of this.progressCallbacks.values()) {
            try { cb({ phase, percent: pct, message: msg }); } catch (e) {}
        }
    }

    /**
     * Download a raw file from GitHub
     */
    static downloadFile(url, destPath) {
        return new Promise((resolve, reject) => {
            const doRequest = (reqUrl) => {
                const proto = reqUrl.startsWith('https') ? https : require('http');
                proto.get(reqUrl, { headers: { 'User-Agent': 'SecureScope/1.0' } }, (res) => {
                    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                        return doRequest(res.headers.location);
                    }
                    if (res.statusCode !== 200) {
                        return reject(new Error(`HTTP ${res.statusCode}`));
                    }
                    const fileStream = fs.createWriteStream(destPath);
                    res.pipe(fileStream);
                    fileStream.on('finish', () => {
                        fileStream.close();
                        resolve(destPath);
                    });
                    fileStream.on('error', (err) => {
                        fs.unlink(destPath, () => {});
                        reject(err);
                    });
                    res.on('error', (err) => {
                        fileStream.destroy();
                        fs.unlink(destPath, () => {});
                        reject(err);
                    });
                }).on('error', reject);
            };
            doRequest(url);
        });
    }

    /**
     * Full sync: download all three nmap files and parse them
     */
    static async syncAll(userId) {
        this.ensureDirs();
        const db = getDatabase();
        const countBefore = db.prepare('SELECT COUNT(*) as c FROM fingerprints').get().c;

        const logEntry = db.prepare(`
            INSERT INTO db_update_log (database_type, source, entries_before, status, triggered_by)
            VALUES ('fingerprints', 'nmap-services + nmap-os-db + nmap-service-probes', ?, 'running', ?)
        `).run(countBefore, userId);
        const logId = logEntry.lastInsertRowid;

        try {
            // Step 1: Download nmap-services
            this.emitProgress('download', 5, 'Lade nmap-services herunter...');
            const servicesPath = path.join(NMAP_DIR, 'nmap-services');
            await this.downloadFile(NMAP_SOURCES.services, servicesPath);

            // Step 2: Download nmap-os-db
            this.emitProgress('download', 20, 'Lade nmap-os-db herunter...');
            const osDbPath = path.join(NMAP_DIR, 'nmap-os-db');
            await this.downloadFile(NMAP_SOURCES.osDb, osDbPath);

            // Step 3: Download nmap-service-probes
            this.emitProgress('download', 35, 'Lade nmap-service-probes herunter...');
            const probesPath = path.join(NMAP_DIR, 'nmap-service-probes');
            await this.downloadFile(NMAP_SOURCES.serviceProbes, probesPath);

            // Step 4: Parse nmap-services
            this.emitProgress('parse', 45, 'Parse nmap-services...');
            const services = await this.parseNmapServices(servicesPath);
            logger.info(`Parsed ${services.length} entries from nmap-services`);

            // Step 5: Parse nmap-os-db
            this.emitProgress('parse', 55, 'Parse nmap-os-db...');
            const osFingerprints = await this.parseNmapOsDb(osDbPath);
            logger.info(`Parsed ${osFingerprints.length} OS fingerprints from nmap-os-db`);

            // Step 6: Parse nmap-service-probes
            this.emitProgress('parse', 65, 'Parse nmap-service-probes...');
            const serviceProbes = await this.parseNmapServiceProbes(probesPath);
            logger.info(`Parsed ${serviceProbes.length} service probes from nmap-service-probes`);

            // Step 7: Import into database
            this.emitProgress('import', 70, 'Importiere in Datenbank...');

            let added = 0, updated = 0;

            // Clear old nmap-sourced entries and re-import for clean sync
            const deleteOld = db.prepare("DELETE FROM fingerprints WHERE source IN ('nmap-services', 'nmap-os-db', 'nmap-service-probes')");

            const insertStmt = db.prepare(`
                INSERT INTO fingerprints (port, protocol, service_name, version_pattern, banner_pattern, os_family, os_version, cpe, description, confidence, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            const importAll = db.transaction(() => {
                // Delete old nmap entries
                const deleted = deleteOld.run();
                logger.info(`Deleted ${deleted.changes} old nmap fingerprints`);

                // Import nmap-services (port → service mapping)
                for (const svc of services) {
                    insertStmt.run(
                        svc.port, svc.protocol, svc.name,
                        null, null, null, null, null,
                        svc.description || `${svc.name} (nmap-services)`,
                        Math.round(svc.frequency * 100) || 50,
                        'nmap-services'
                    );
                    added++;
                }

                // Import OS fingerprints
                for (const os of osFingerprints) {
                    // OS fingerprints don't have a specific port, use 0 as marker
                    insertStmt.run(
                        0, 'tcp', os.name,
                        os.version || null, null,
                        os.osFamily, os.osVersion,
                        os.cpe || null,
                        os.description || `OS: ${os.name}`,
                        os.confidence || 70,
                        'nmap-os-db'
                    );
                    added++;
                }

                // Import service probes (version detection patterns)
                for (const probe of serviceProbes) {
                    for (const match of probe.matches) {
                        insertStmt.run(
                            match.port || 0, 'tcp',
                            match.service,
                            match.versionPattern || null,
                            match.pattern || null,
                            match.osFamily || null, null,
                            match.cpe || null,
                            match.info || `${match.service} probe match`,
                            match.confidence || 75,
                            'nmap-service-probes'
                        );
                        added++;
                    }
                }
            });

            importAll();

            const countAfter = db.prepare('SELECT COUNT(*) as c FROM fingerprints').get().c;

            db.prepare(`
                UPDATE db_update_log SET entries_added = ?, entries_updated = ?, entries_after = ?,
                status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(added, updated, countAfter, logId);

            this.emitProgress('done', 100, `Fertig! ${added} Fingerprints importiert. Gesamt: ${countAfter}`);

            logger.info(`Nmap sync completed: ${added} added (${countBefore} → ${countAfter})`);

            return {
                success: true,
                message: `Fingerprint-Datenbank aktualisiert: ${added} Einträge aus Nmap-Quellen importiert`,
                stats: {
                    before: countBefore, added, updated, after: countAfter,
                    sources: {
                        services: services.length,
                        osFingerprints: osFingerprints.length,
                        serviceProbes: serviceProbes.length
                    }
                }
            };

        } catch (err) {
            db.prepare(`
                UPDATE db_update_log SET status = 'error', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?
            `).run(err.message, logId);
            this.emitProgress('error', 0, `Fehler: ${err.message}`);
            logger.error('Nmap sync error:', err);
            throw err;
        }
    }

    /**
     * Parse nmap-services file
     * Format: service_name\tport/protocol\tfrequency\t# comment
     */
    static async parseNmapServices(filePath) {
        const results = [];
        const readline = require('readline');
        const fileStream = fs.createReadStream(filePath);
        const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

        for await (const line of rl) {
            if (line.startsWith('#') || line.trim() === '') continue;

            const parts = line.split('\t');
            if (parts.length < 3) continue;

            const name = parts[0].trim();
            const portProto = parts[1].trim().split('/');
            if (portProto.length !== 2) continue;

            const port = parseInt(portProto[0], 10);
            const protocol = portProto[1];
            const frequency = parseFloat(parts[2]) || 0;

            // Skip very uncommon services (frequency < 0.0001) to keep DB manageable
            if (frequency < 0.000050 && port > 1024) continue;
            // Always include well-known ports
            if (port > 65535 || port < 0) continue;

            const comment = parts[3] ? parts[3].replace(/^#\s*/, '').trim() : null;

            results.push({
                name,
                port,
                protocol,
                frequency,
                description: comment || name
            });
        }

        return results;
    }

    /**
     * Parse nmap-os-db file
     * Format: Fingerprint blocks starting with "Fingerprint" line
     */
    static async parseNmapOsDb(filePath) {
        const results = [];
        const readline = require('readline');
        const fileStream = fs.createReadStream(filePath);
        const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
        let current = null;

        for await (const line of rl) {
            if (line.startsWith('Fingerprint ')) {
                // Save previous
                if (current) results.push(current);

                const name = line.substring(12).trim();
                current = {
                    name,
                    osFamily: null,
                    osVersion: null,
                    cpe: null,
                    description: name,
                    confidence: 80,
                    version: null
                };
            } else if (line.startsWith('Class ') && current) {
                // Class vendor | OS family | OS generation | device type
                const classData = line.substring(6).trim();
                const parts = classData.split('|').map(p => p.trim());
                if (parts.length >= 2) {
                    current.osFamily = parts[1] || current.osFamily;
                    if (parts.length >= 3) current.osVersion = parts[2] || null;
                    current.version = parts[2] || null;
                }
            } else if (line.startsWith('CPE ') && current) {
                const cpe = line.substring(4).trim();
                if (!current.cpe) current.cpe = cpe;
                else current.cpe += '; ' + cpe;
            }
        }

        // Don't forget the last one
        if (current) results.push(current);

        return results;
    }

    /**
     * Parse nmap-service-probes file
     * Format: Probe blocks with match directives
     */
    static async parseNmapServiceProbes(filePath) {
        const results = [];
        const readline = require('readline');
        const fileStream = fs.createReadStream(filePath);
        const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });
        let currentProbe = null;

        for await (const line of rl) {
            if (line.startsWith('#') || line.trim() === '') continue;

            if (line.startsWith('Probe ')) {
                if (currentProbe && currentProbe.matches.length > 0) {
                    results.push(currentProbe);
                }
                // Probe TCP/UDP name q|...|
                const parts = line.match(/^Probe\s+(TCP|UDP)\s+(\S+)\s+q\|(.*)$/);
                currentProbe = {
                    protocol: parts ? parts[1].toLowerCase() : 'tcp',
                    name: parts ? parts[2] : 'unknown',
                    probeString: parts ? parts[3] : '',
                    matches: [],
                    ports: [],
                    sslPorts: []
                };
            } else if (line.startsWith('ports ') && currentProbe) {
                const portStr = line.substring(6).trim();
                currentProbe.ports = portStr.split(',').map(p => {
                    p = p.trim();
                    if (p.includes('-')) {
                        const [start, end] = p.split('-').map(Number);
                        return { start, end };
                    }
                    return { start: parseInt(p, 10), end: parseInt(p, 10) };
                }).filter(p => !isNaN(p.start));
            } else if (line.startsWith('sslports ') && currentProbe) {
                const portStr = line.substring(9).trim();
                currentProbe.sslPorts = portStr.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
            } else if (line.startsWith('match ') && currentProbe) {
                const parsed = this.parseMatchLine(line, currentProbe);
                if (parsed) {
                    currentProbe.matches.push(parsed);
                }
            } else if (line.startsWith('softmatch ') && currentProbe) {
                const parsed = this.parseSoftMatchLine(line, currentProbe);
                if (parsed) {
                    parsed.confidence = Math.max(parsed.confidence - 15, 40);
                    currentProbe.matches.push(parsed);
                }
            }
        }

        if (currentProbe && currentProbe.matches.length > 0) {
            results.push(currentProbe);
        }

        return results;
    }

    /**
     * Parse a match line from nmap-service-probes
     * match service m|pattern|flags [p/product/] [v/version/] [i/info/] [h/hostname/] [o/os/] [d/device/] [cpe:/...]
     */
    static parseMatchLine(line, probe) {
        try {
            // match service m|...|[flags] [metadata]
            const serviceMatch = line.match(/^match\s+(\S+)\s+m([|/%=])(.+?)\2([si]*)\s*(.*)/);
            if (!serviceMatch) return null;

            const service = serviceMatch[1];
            const pattern = serviceMatch[3].substring(0, 200); // Truncate long patterns
            const flags = serviceMatch[4];
            const metadata = serviceMatch[5] || '';

            let versionPattern = null;
            let info = null;
            let osFamily = null;
            let cpe = null;
            let port = null;

            // Extract version: v/version/
            const vMatch = metadata.match(/v\/([^/]*)\//);
            if (vMatch) versionPattern = vMatch[1].replace(/\$\d/g, '*');

            // Extract product: p/product/
            const pMatch = metadata.match(/p\/([^/]*)\//);
            if (pMatch) info = pMatch[1].replace(/\$\d/g, '*');

            // Extract info: i/info/
            const iMatch = metadata.match(/i\/([^/]*)\//);
            if (iMatch) info = (info ? info + ' - ' : '') + iMatch[1].replace(/\$\d/g, '*');

            // Extract OS: o/os/
            const oMatch = metadata.match(/o\/([^/]*)\//);
            if (oMatch) osFamily = oMatch[1].replace(/\$\d/g, '*');

            // Extract CPE
            const cpeMatch = metadata.match(/cpe:\/([^\s/]+(?:\/[^\s/]*)*)/);
            if (cpeMatch) cpe = 'cpe:/' + cpeMatch[1];

            // Get primary port from probe
            if (probe.ports.length > 0) {
                port = probe.ports[0].start;
            }

            return {
                service,
                pattern: pattern.substring(0, 200),
                versionPattern: versionPattern?.substring(0, 100),
                info: info?.substring(0, 200),
                osFamily: osFamily?.substring(0, 100),
                cpe: cpe?.substring(0, 200),
                port,
                confidence: 80
            };
        } catch (e) {
            return null;
        }
    }

    /**
     * Parse a softmatch line (lower confidence)
     */
    static parseSoftMatchLine(line, probe) {
        try {
            const newLine = line.replace(/^softmatch/, 'match');
            const result = this.parseMatchLine(newLine, probe);
            if (result) result.confidence = 60;
            return result;
        } catch (e) {
            return null;
        }
    }
}

module.exports = NmapSyncService;