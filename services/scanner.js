const { spawn } = require('child_process');
const { getDatabase } = require('../config/database');
const logger = require('./logger');
const ExploitService = require('./exploitService');
const emailService = require('./emailService');
const NmapParser = require('./nmapParser');
const CVEService = require('./cveService');
const { EventEmitter } = require('events');
const IPCIDR_MODULE = require('ip-cidr');
const IPCIDR = IPCIDR_MODULE.default || IPCIDR_MODULE;
const scannerConfig = require('../config/scanner');

class ScannerService extends EventEmitter {
    constructor() {
        super();
        this.activeScans = new Map(); // scanId -> { process, aborted }
        this.MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS) || scannerConfig.DEFAULT_MAX_CONCURRENT;
        this.SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT) || scannerConfig.DEFAULT_SCAN_TIMEOUT;
    }

    // Initialize scanner service (must be called after DB init)
    initialize() {
        // Reset zombie scans on startup
        try {
            const db = getDatabase();
            const res = db.prepare("UPDATE scans SET status = 'failed', error_message = 'System restart (Zombie scan)', completed_at = CURRENT_TIMESTAMP WHERE status = 'running'").run();
            if (res.changes > 0) {
                logger.info(`Reset ${res.changes} zombie scans to failed state.`);
            }
        } catch (e) {
            console.error('Failed to reset zombie scans:', e);
        }
    }

    // Top 100 ports for quick scan
    static get TOP_100_PORTS() {
        return scannerConfig.TOP_100_PORTS;
    }

    // Top 1000 ports for standard scan
    static get TOP_1000_PORTS() {
        return scannerConfig.TOP_1000_PORTS;
    }

    // Validate IP address
    static isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        return ipv4Regex.test(ip);
    }

    // Validate CIDR notation
    static isValidCIDR(cidr) {
        return IPCIDR.isValidCIDR(cidr);
    }

    // Check if IP is in private range (RFC 1918)
    static isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        if (parts[0] === 10) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 127) return true;
        return false;
    }

    // Validate target (IP or CIDR)
    static validateTarget(target) {
        const trimmed = target.trim();

        if (trimmed.includes('/')) {
            if (!ScannerService.isValidCIDR(trimmed)) {
                return { valid: false, error: 'Ungültiger CIDR-Bereich' };
            }
            const prefix = parseInt(trimmed.split('/')[1]);
            if (prefix < 24) {
                return { valid: false, error: 'CIDR-Bereich zu groß. Maximal /24 (256 Adressen) erlaubt.' };
            }
            return { valid: true, type: 'cidr', target: trimmed };
        }

        if (!ScannerService.isValidIP(trimmed)) {
            return { valid: false, error: 'Ungültige IP-Adresse' };
        }
        return { valid: true, type: 'single', target: trimmed };
    }

    // Validate port specification
    static validatePorts(ports) {
        if (!ports) return { valid: false, error: 'Keine Ports angegeben' };
        const portParts = ports.split(',');
        for (const part of portParts) {
            const trimmed = part.trim();
            if (trimmed.includes('-')) {
                // Range validation: strictly digits-digits
                if (!/^\d+-\d+$/.test(trimmed)) {
                    return { valid: false, error: `Ungültiges Port-Bereichs-Format: ${trimmed}` };
                }
                const [startStr, endStr] = trimmed.split('-');
                const start = parseInt(startStr, 10);
                const end = parseInt(endStr, 10);

                if (start < 1 || end > 65535 || start > end) {
                    return { valid: false, error: `Ungültiger Port-Bereich (1-65535, Start <= Ende): ${trimmed}` };
                }
            } else {
                // Single port validation: strictly digits
                if (!/^\d+$/.test(trimmed)) {
                    return { valid: false, error: `Ungültiges Port-Format: ${trimmed}` };
                }
                const port = parseInt(trimmed, 10);
                if (port < 1 || port > 65535) {
                    return { valid: false, error: `Ungültige Port-Nummer (1-65535): ${trimmed}` };
                }
            }
        }
        return { valid: true };
    }

    // Get port range based on scan type
    static getPortRange(scanType, customPorts) {
        switch (scanType) {
            case 'quick': return ScannerService.TOP_100_PORTS;
            case 'standard': return ScannerService.TOP_1000_PORTS;
            case 'full': return scannerConfig.FULL_PORT_RANGE;
            case 'custom': return customPorts;
            default: return ScannerService.TOP_100_PORTS;
        }
    }

    // Get active scan count
    getActiveScanCount() {
        return this.activeScans.size;
    }

    // Expand CIDR to list of IPs
    static expandCIDR(cidr) {
        try {
            const ipCidr = new IPCIDR(cidr);
            return ipCidr.toArray();
        } catch {
            return [];
        }
    }

    // ============================================
    // SCAN EXECUTION
    // ============================================

    // Start a new scan
    async startScan(userId, target, scanType, customPorts = null, stealthMode = false) {
        const db = getDatabase();

        // Check concurrent scan limit
        if (this.activeScans.size >= this.MAX_CONCURRENT) {
            throw new Error(`Maximale Anzahl gleichzeitiger Scans erreicht (${this.MAX_CONCURRENT})`);
        }

        // Validate target
        const targetValidation = ScannerService.validateTarget(target);
        if (!targetValidation.valid) {
            throw new Error(targetValidation.error);
        }

        // Check private IP restriction
        const allowExternal = process.env.ALLOW_EXTERNAL_SCANS === 'true';
        if (!allowExternal) {
            const ipToCheck = targetValidation.type === 'cidr'
                ? target.split('/')[0]
                : target;
            if (!ScannerService.isPrivateIP(ipToCheck)) {
                throw new Error('Scans außerhalb privater Netzwerke sind nicht erlaubt. Aktivieren Sie ALLOW_EXTERNAL_SCANS in der Konfiguration.');
            }
        }

        // Stealth mode requires root privileges
        if (stealthMode) {
            const isRoot = process.getuid && process.getuid() === 0;
            if (!isRoot) {
                throw new Error('Stealth-Scan erfordert Root-Rechte. Bitte starten Sie den Server mit erhöhten Berechtigungen.');
            }
        }

        // Get port range
        const portRange = ScannerService.getPortRange(scanType, customPorts);

        // Validate custom ports
        if (scanType === 'custom') {
            const portValidation = ScannerService.validatePorts(customPorts);
            if (!portValidation.valid) {
                throw new Error(portValidation.error);
            }
        }

        // Store scan type with stealth suffix for identification
        const effectiveScanType = stealthMode ? `${scanType}_stealth` : scanType;

        // Create scan record in database
        const result = db.prepare(
            'INSERT INTO scans (user_id, scan_type, target, port_range, status) VALUES (?, ?, ?, ?, ?)'
        ).run(userId, effectiveScanType, target, portRange, 'running');

        const scanId = result.lastInsertRowid;

        logger.info(`Scan ${scanId} started: type=${effectiveScanType}, target=${target}, ports=${portRange}, stealth=${stealthMode}`);
        logger.audit('SCAN_STARTED', { scanId, userId, scanType: effectiveScanType, target, stealthMode });

        // Execute scan asynchronously
        this._executeScan(scanId, targetValidation, portRange, scanType, stealthMode);

        return {
            id: scanId,
            status: 'running',
            scanType: effectiveScanType,
            target,
            portRange
        };
    }

    // Build Nmap command arguments
    _buildNmapArgs(target, portRange, scanType, stealthMode = false) {
        const args = [];

        if (stealthMode) {
            // Stealth SYN scan: uses half-open TCP connections
            // Harder to detect by IDS/firewalls since connections are never fully established
            args.push(
                '-sS',                       // SYN stealth scan (half-open)
                '-T2',                       // Polite timing (slower, stealthier)
                '-p', portRange,             // Port range
                '-oX', '-',                  // XML output to stdout
                '--open',                    // Only show open ports
                '--host-timeout', '600s',    // 10 min timeout (stealth is slower)
                '--max-retries', '1',        // Fewer retries to reduce footprint
                '--max-rate', '100',         // Limit packet rate for stealth
                '-f',                        // Fragment packets (harder to detect)
                '--data-length', '24',       // Append random data to packets
            );
        } else {
            args.push(
                '-sV',                      // Service/version detection
                '--version-all',            // Try ALL probes for version detection (critical for legacy OS)
                '--version-intensity', '5', // Maximum intensity for comprehensive version detection
                '-sC',                      // Default scripts (vuln detection, enum)
                '-T4',                       // Aggressive timing (fast)
                '-p', portRange,             // Port range
                '-oX', '-',                  // XML output to stdout
                '--open',                    // Only show open ports
                '--host-timeout', '300s',    // 5 min timeout per host
                '--max-retries', '2',        // Max retries
            );

            // For full scan, increase timeout
            if (scanType === 'full') {
                const idx = args.indexOf('300s');
                if (idx !== -1) args[idx] = '600s';
            }
        }

        // Add OS detection (requires root)
        const isRoot = process.getuid && process.getuid() === 0;
        if (isRoot) {
            args.push('-O', '--osscan-guess', '--osscan-limit');
        }

        args.push(target);
        return args;
    }

    // Internal: Execute the scan using Nmap
    async _executeScan(scanId, targetValidation, portRange, scanType, stealthMode = false) {
        const db = getDatabase();
        let scanControl = { aborted: false, process: null };
        this.activeScans.set(scanId, scanControl);

        // Set timeout
        const timeoutHandle = setTimeout(() => {
            this.stopScan(scanId);
            logger.warn(`Scan ${scanId} timed out after ${this.SCAN_TIMEOUT}ms`);
        }, this.SCAN_TIMEOUT);

        try {
            const target = targetValidation.target;
            const nmapArgs = this._buildNmapArgs(target, portRange, scanType, stealthMode);

            logger.info(`Scan ${scanId}: Running nmap ${nmapArgs.join(' ')} (stealth=${stealthMode})`);

            // Update progress - scanning phase
            db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(10, scanId);
            this.emit('scanProgress', { scanId, progress: 10, phase: 'scanning', message: 'Nmap-Scan mit Service-Detection läuft...' });

            // Execute Nmap
            const nmapResult = await this._runNmap(nmapArgs, scanControl, scanId);

            if (scanControl.aborted) {
                db.prepare('UPDATE scans SET status = ?, progress = 100, completed_at = CURRENT_TIMESTAMP WHERE id = ?')
                    .run('aborted', scanId);
                this.emit('scanComplete', { scanId, status: 'aborted', resultCount: 0 });
                logger.info(`Scan ${scanId} was aborted`);
                return;
            }

            // Update progress - parsing phase
            db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(60, scanId);
            this.emit('scanProgress', { scanId, progress: 60, phase: 'parsing', message: 'Ergebnisse werden verarbeitet...' });

            // Parse Nmap XML output
            const results = NmapParser.parseXML(nmapResult);
            logger.info(`Scan ${scanId}: Nmap found ${results.length} open ports with service info`);

            // Process results
            await this._processResults(scanId, results, db);

        } catch (err) {
            logger.error(`Scan ${scanId} failed:`, err);
            db.prepare(
                'UPDATE scans SET status = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?'
            ).run('failed', err.message, scanId);
            this.emit('scanError', { scanId, error: err.message });
        } finally {
            clearTimeout(timeoutHandle);
            this.activeScans.delete(scanId);
        }
    }

    // Common result processing for both scan methods
    async _processResults(scanId, results, db) {
        // Save results to database
        if (results.length > 0) {
            const insertStmt = db.prepare(`
                INSERT INTO scan_results (scan_id, ip_address, port, protocol, service, state, risk_level,
                    service_product, service_version, service_extra, service_cpe, banner, os_name, os_accuracy)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            const insertMany = db.transaction((items) => {
                for (const item of items) {
                    insertStmt.run(
                        scanId, item.ip, item.port, item.protocol,
                        item.service, item.state, item.riskLevel,
                        item.service_product, item.service_version,
                        item.service_extra, item.service_cpe,
                        item.banner, item.os_name, item.os_accuracy
                    );
                }
            });
            insertMany(results);
        }

        // Update progress - analysis phase
        db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(80, scanId);
        this.emit('scanProgress', { scanId, progress: 80, phase: 'analysis', message: 'Sicherheitsanalyse (CVE + Exploit Matching)...' });

        // Post-scan analysis pipeline
        let exploitMatches = [];
        let cveMatches = [];

        if (results.length > 0) {
            // Match against CVE database using detected service versions
            try {
                cveMatches = CVEService.matchCVEs(scanId);
                logger.info(`Scan ${scanId}: ${cveMatches.length} CVE matches found`);
            } catch (cveErr) {
                logger.error(`CVE matching failed for scan ${scanId}:`, cveErr);
            }

            // Match against exploit database
            try {
                exploitMatches = ExploitService.matchScanResults(scanId);
                logger.info(`Scan ${scanId}: ${exploitMatches.length} exploit matches found`);
            } catch (exploitErr) {
                logger.error(`Exploit matching failed for scan ${scanId}:`, exploitErr);
            }
        }

        // Mark scan as completed
        db.prepare(
            'UPDATE scans SET status = ?, progress = 100, completed_at = CURRENT_TIMESTAMP WHERE id = ?'
        ).run('completed', scanId);

        const exploitSummary = ExploitService.getScanExploitSummary(scanId);

        this.emit('scanComplete', {
            scanId, status: 'completed', resultCount: results.length,
            cveMatches: cveMatches.length,
            exploits: exploitSummary
        });

        logger.info(`Scan ${scanId} completed: ${results.length} open ports, ${cveMatches.length} CVEs, ${exploitMatches.length} exploits`);
        logger.audit('SCAN_COMPLETED', {
            scanId, status: 'completed', resultCount: results.length,
            cveCount: cveMatches.length, exploitCount: exploitMatches.length
        });

        // Send email notifications
        try {
            const scan = this.getScanStatus(scanId);
            const critCount = cveMatches.filter(c => c.severity === 'critical').length;
            await emailService.notifyScanComplete(scan.user_id, scan, results.length, { critical: critCount });

            if (critCount > 0) {
                const criticalCVEs = cveMatches.filter(c => c.severity === 'critical');
                await emailService.notifyCriticalFound(scan.user_id, scan, criticalCVEs);
            }
        } catch (emailErr) {
            logger.error(`Email notification failed for scan ${scanId}:`, emailErr);
        }
    }

    // Run Nmap as child process and collect XML output
    _runNmap(args, scanControl, scanId) {
        return new Promise((resolve, reject) => {
            let xmlOutput = '';
            let stderrOutput = '';

            const nmapProcess = spawn('nmap', args, {
                stdio: ['ignore', 'pipe', 'pipe']
            });

            scanControl.process = nmapProcess;

            nmapProcess.stdout.on('data', (data) => {
                xmlOutput += data.toString();
            });

            nmapProcess.stderr.on('data', (data) => {
                const line = data.toString().trim();
                stderrOutput += line + '\n';

                // Parse Nmap progress from stderr
                const progressMatch = line.match(/About\s+([\d.]+)%\s+done/);
                if (progressMatch) {
                    const nmapProgress = parseFloat(progressMatch[1]);
                    // Map nmap progress (0-100) to our range (10-60)
                    const mappedProgress = Math.round(10 + (nmapProgress / 100) * 50);
                    this.emit('scanProgress', {
                        scanId, progress: mappedProgress,
                        phase: 'scanning',
                        message: `Nmap-Scan: ${Math.round(nmapProgress)}% abgeschlossen`
                    });
                }
            });

            nmapProcess.on('close', (code) => {
                scanControl.process = null;

                if (scanControl.aborted) {
                    resolve('');
                    return;
                }

                if (code !== 0 && !xmlOutput.includes('</nmaprun>')) {
                    logger.warn(`Nmap exited with code ${code}. stderr: ${stderrOutput.substring(0, 500)}`);
                    if (xmlOutput.length > 0) {
                        resolve(xmlOutput);
                    } else {
                        reject(new Error(`Nmap-Scan fehlgeschlagen (Exit-Code: ${code}). ${stderrOutput.substring(0, 200)}`));
                    }
                } else {
                    resolve(xmlOutput);
                }
            });

            nmapProcess.on('error', (err) => {
                scanControl.process = null;
                reject(new Error(`Nmap konnte nicht gestartet werden: ${err.message}`));
            });
        });
    }

    // ============================================
    // CVE MATCHING (using real service versions from Nmap)
    // ============================================

    getScanCVEs(scanId) {
        return CVEService.getScanCVEs(scanId);
    }

    getScanCVESummary(scanId) {
        return CVEService.getScanCVESummary(scanId);
    }

    /**
     * Get dashboard statistics for a user
     */
    getDashboardStats(userId) {
        const db = getDatabase();

        // Single query for counts
        const stats = db.prepare(`
            SELECT
                (SELECT COUNT(*) FROM scans WHERE user_id = ?) as totalScans,
                (SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'completed') as completedScans,
                (SELECT COUNT(*) FROM scan_results sr JOIN scans s ON sr.scan_id = s.id WHERE s.user_id = ? AND sr.risk_level = 'critical') as criticalPorts,
                (SELECT COUNT(*) FROM scan_vulnerabilities sv JOIN scans s ON sv.scan_id = s.id WHERE s.user_id = ?) as totalVulnerabilities
        `).get(userId, userId, userId, userId);

        // Active scans
        const activeScansCount = this.getActiveScanCount();
        const activeScanRow = db.prepare("SELECT * FROM scans WHERE user_id = ? AND status = 'running' ORDER BY started_at DESC LIMIT 1").get(userId);

        // Recent scans with result counts and vuln counts
        // Optimized: Use JOIN and GROUP BY with a derived table to avoid correlated subqueries and maintain performance
        const recentScans = db.prepare(`
            SELECT s.*,
                   COUNT(DISTINCT sr.id) as result_count,
                   COUNT(DISTINCT sv.id) as vuln_count
            FROM (
                SELECT * FROM scans
                WHERE user_id = ?
                ORDER BY started_at DESC LIMIT 10
            ) s
            LEFT JOIN scan_results sr ON sr.scan_id = s.id
            LEFT JOIN scan_vulnerabilities sv ON sv.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.started_at DESC
        `).all(userId);

        return {
            totalScans: stats.totalScans,
            completedScans: stats.completedScans,
            criticalPorts: stats.criticalPorts,
            totalVulnerabilities: stats.totalVulnerabilities || 0,
            activeScans: activeScansCount,
            activeScan: activeScanRow || null,
            recentScans
        };
    }

    // ============================================
    // SCAN MANAGEMENT
    // ============================================

    // Stop a running scan
    stopScan(scanId) {
        const scanControl = this.activeScans.get(scanId);
        if (scanControl) {
            scanControl.aborted = true;
            if (scanControl.process) {
                try {
                    scanControl.process.kill('SIGTERM');
                    setTimeout(() => {
                        try { if (scanControl.process) scanControl.process.kill('SIGKILL'); } catch (e) {}
                    }, 5000);
                } catch (e) {}
            }
            logger.info(`Scan ${scanId} abort requested`);
            logger.audit('SCAN_ABORTED', { scanId });
            return true;
        } else {
            // Handle zombie scans (process gone but DB says running)
            const db = getDatabase();
            const scan = db.prepare('SELECT status FROM scans WHERE id = ?').get(scanId);
            if (scan && scan.status === 'running') {
                db.prepare("UPDATE scans SET status = 'aborted', completed_at = CURRENT_TIMESTAMP WHERE id = ?").run(scanId);
                logger.info(`Zombie scan ${scanId} manually aborted`);
                logger.audit('SCAN_ABORTED_MANUAL', { scanId });
                return true;
            }
        }
        return false;
    }

    // Get scan status
    getScanStatus(scanId) {
        const db = getDatabase();
        const scan = db.prepare(
            'SELECT id, user_id, scan_type, target, port_range, status, progress, started_at, completed_at, error_message FROM scans WHERE id = ?'
        ).get(scanId);
        return scan || null;
    }

    // Get scan results with pagination
    getScanResults(scanId, page = 1, limit = 50) {
        const db = getDatabase();
        const offset = (page - 1) * limit;

        const results = db.prepare(
            'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port LIMIT ? OFFSET ?'
        ).all(scanId, limit, offset);

        const total = db.prepare(
            'SELECT COUNT(*) as count FROM scan_results WHERE scan_id = ?'
        ).get(scanId);

        return {
            results,
            pagination: {
                page, limit,
                total: total.count,
                totalPages: Math.ceil(total.count / limit)
            }
        };
    }

    // Get all results for a scan (for export)
    getAllScanResults(scanId) {
        const db = getDatabase();
        return db.prepare(
            'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port'
        ).all(scanId);
    }

    // Get scan history with filters
    getScanHistory(userId, filters = {}) {
        const db = getDatabase();
        let query = 'SELECT s.*, COUNT(DISTINCT sr.id) as result_count, COUNT(DISTINCT sv.id) as vuln_count FROM scans s LEFT JOIN scan_results sr ON s.id = sr.scan_id LEFT JOIN scan_vulnerabilities sv ON s.id = sv.scan_id WHERE s.user_id = ?';
        const params = [userId];

        if (filters.dateFrom) { query += ' AND s.started_at >= ?'; params.push(filters.dateFrom); }
        if (filters.dateTo) { query += ' AND s.started_at <= ?'; params.push(filters.dateTo); }
        if (filters.scanType) { query += ' AND s.scan_type = ?'; params.push(filters.scanType); }
        if (filters.target) { query += ' AND s.target LIKE ?'; params.push(`%${filters.target}%`); }
        if (filters.status) { query += ' AND s.status = ?'; params.push(filters.status); }

        query += ' GROUP BY s.id ORDER BY s.started_at DESC';

        const page = filters.page || 1;
        const limit = filters.limit || 20;
        const offset = (page - 1) * limit;

        const countQuery = query.replace('SELECT s.*, COUNT(DISTINCT sr.id) as result_count, COUNT(DISTINCT sv.id) as vuln_count', 'SELECT COUNT(DISTINCT s.id) as count').replace(' GROUP BY s.id ORDER BY s.started_at DESC', '');
        const total = db.prepare(countQuery).get(...params);

        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const scans = db.prepare(query).all(...params);

        return {
            scans,
            pagination: {
                page, limit,
                total: total.count,
                totalPages: Math.ceil(total.count / limit)
            }
        };
    }

    // Compare two scans
    compareScans(scanId1, scanId2) {
        const db = getDatabase();

        const results1 = db.prepare(
            'SELECT ip_address, port, protocol, service, state, risk_level, service_product, service_version, banner FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port'
        ).all(scanId1);

        const results2 = db.prepare(
            'SELECT ip_address, port, protocol, service, state, risk_level, service_product, service_version, banner FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port'
        ).all(scanId2);

        const scan1 = this.getScanStatus(scanId1);
        const scan2 = this.getScanStatus(scanId2);

        const set1 = new Set(results1.map(r => `${r.ip_address}:${r.port}`));
        const set2 = new Set(results2.map(r => `${r.ip_address}:${r.port}`));

        const onlyInScan1 = results1.filter(r => !set2.has(`${r.ip_address}:${r.port}`));
        const onlyInScan2 = results2.filter(r => !set1.has(`${r.ip_address}:${r.port}`));
        const inBoth = results1.filter(r => set2.has(`${r.ip_address}:${r.port}`));

        return {
            scan1: { info: scan1, resultCount: results1.length },
            scan2: { info: scan2, resultCount: results2.length },
            comparison: {
                onlyInScan1, onlyInScan2, inBoth,
                newPorts: onlyInScan2.length,
                closedPorts: onlyInScan1.length,
                unchangedPorts: inBoth.length
            }
        };
    }
}

// Singleton instance
const scannerService = new ScannerService();

module.exports = scannerService;
