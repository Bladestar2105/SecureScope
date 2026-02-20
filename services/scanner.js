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

class ScannerService extends EventEmitter {
    constructor() {
        super();
        this.activeScans = new Map(); // scanId -> { process, aborted }
        this.MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS) || 3;
        this.SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT) || 600000; // 10 min default
    }

    // Top 100 ports for quick scan
    static get TOP_100_PORTS() {
        return '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157';
    }

    // Top 1000 ports for standard scan
    static get TOP_1000_PORTS() {
        return '1-1024,1025-1030,1080,1099,1110,1194,1433,1434,1521,1604,1723,1755,1900,2000,2001,2049,2082,2083,2086,2087,2095,2096,2121,2181,2222,2375,2376,2717,3000,3128,3268,3269,3306,3389,3690,3986,4443,4444,4567,4711,4712,4848,4899,5000,5001,5009,5050,5051,5060,5061,5101,5190,5222,5223,5357,5432,5555,5601,5631,5632,5666,5672,5800,5900,5901,5984,5985,5986,6000,6001,6379,6443,6646,6660-6669,7000,7001,7002,7070,7071,7077,7078,7474,7547,7548,8000,8001,8008,8009,8010,8020,8042,8060,8069,8080,8081,8082,8083,8088,8090,8091,8139,8140,8161,8200,8222,8333,8334,8443,8444,8500,8649,8834,8880,8888,8889,8983,9000,9001,9002,9042,9043,9060,9080,9090,9091,9100,9200,9300,9418,9443,9876,9990,9999,10000,10001,10050,10051,10250,10443,11211,11300,12345,13579,14147,16010,16080,18080,19888,20000,20547,21025,22222,23023,25565,27017,27018,28017,30000,32400,32768,33060,37777,40000,44443,47001,48899,49152-49157,50000,50070,54321,55553,55555,60000,60010,60030,61616,63790,64738';
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
                const [start, end] = trimmed.split('-').map(Number);
                if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
                    return { valid: false, error: `Ungültiger Port-Bereich: ${trimmed}` };
                }
            } else {
                const port = parseInt(trimmed);
                if (isNaN(port) || port < 1 || port > 65535) {
                    return { valid: false, error: `Ungültige Port-Nummer: ${trimmed}` };
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
            case 'full': return '1-65535';
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
    async startScan(userId, target, scanType, customPorts = null) {
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

        // Get port range
        const portRange = ScannerService.getPortRange(scanType, customPorts);

        // Validate custom ports
        if (scanType === 'custom') {
            const portValidation = ScannerService.validatePorts(customPorts);
            if (!portValidation.valid) {
                throw new Error(portValidation.error);
            }
        }

        // Create scan record in database
        const result = db.prepare(
            'INSERT INTO scans (user_id, scan_type, target, port_range, status) VALUES (?, ?, ?, ?, ?)'
        ).run(userId, scanType, target, portRange, 'running');

        const scanId = result.lastInsertRowid;

        logger.info(`Scan ${scanId} started: type=${scanType}, target=${target}, ports=${portRange}`);
        logger.audit('SCAN_STARTED', { scanId, userId, scanType, target });

        // Execute scan asynchronously
        this._executeScan(scanId, targetValidation, portRange, scanType);

        return {
            id: scanId,
            status: 'running',
            scanType,
            target,
            portRange
        };
    }

    // Build Nmap command arguments
    _buildNmapArgs(target, portRange, scanType) {
        const args = [
            '-sV',                      // Service/version detection
            '--version-intensity', '5',  // Balanced version detection intensity (0-9)
            '-T4',                       // Aggressive timing (fast)
            '-p', portRange,             // Port range
            '-oX', '-',                  // XML output to stdout
            '--open',                    // Only show open ports
            '--host-timeout', '300s',    // 5 min timeout per host
            '--max-retries', '2',        // Max retries
        ];

        // For quick scan, reduce version detection intensity for speed
        if (scanType === 'quick') {
            args[2] = '3';
        }

        // For full scan, increase timeout
        if (scanType === 'full') {
            const idx = args.indexOf('300s');
            if (idx !== -1) args[idx] = '600s';
        }

        // Add OS detection for standard and full scans (requires root)
        const isRoot = process.getuid && process.getuid() === 0;
        if ((scanType === 'standard' || scanType === 'full') && isRoot) {
            args.push('-O', '--osscan-guess');
        }

        args.push(target);
        return args;
    }

    // Internal: Execute the scan using Nmap
    async _executeScan(scanId, targetValidation, portRange, scanType) {
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
            const nmapArgs = this._buildNmapArgs(target, portRange, scanType);

            logger.info(`Scan ${scanId}: Running nmap ${nmapArgs.join(' ')}`);

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
        // Optimized: Use correlated subqueries instead of JOIN+GROUP BY to avoid Cartesian product
        const recentScans = db.prepare(`
            SELECT s.*,
                   (SELECT COUNT(*) FROM scan_results sr WHERE sr.scan_id = s.id) as result_count,
                   (SELECT COUNT(*) FROM scan_vulnerabilities sv WHERE sv.scan_id = s.id) as vuln_count
            FROM scans s
            WHERE s.user_id = ?
            ORDER BY s.started_at DESC LIMIT 10
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
        let query = 'SELECT s.*, COUNT(sr.id) as result_count FROM scans s LEFT JOIN scan_results sr ON s.id = sr.scan_id WHERE s.user_id = ?';
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

        const countQuery = query.replace('SELECT s.*, COUNT(sr.id) as result_count', 'SELECT COUNT(DISTINCT s.id) as count').replace(' GROUP BY s.id ORDER BY s.started_at DESC', '');
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
