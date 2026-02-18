const evilscan = require('evilscan');
const { getDatabase } = require('../config/database');
const logger = require('./logger');
const { EventEmitter } = require('events');
const IPCIDR = require('ip-cidr');

class ScannerService extends EventEmitter {
    constructor() {
        super();
        this.activeScans = new Map(); // scanId -> { scanner, aborted }
        this.MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS) || 3;
        this.SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT) || 300000;
    }

    // Known critical ports and their risk levels
    static get CRITICAL_PORTS() {
        return {
            21: { service: 'FTP', risk: 'critical', description: 'File Transfer Protocol - oft unverschlüsselt' },
            22: { service: 'SSH', risk: 'safe', description: 'Secure Shell' },
            23: { service: 'Telnet', risk: 'critical', description: 'Telnet - unverschlüsselte Verbindung' },
            25: { service: 'SMTP', risk: 'warning', description: 'Simple Mail Transfer Protocol' },
            53: { service: 'DNS', risk: 'safe', description: 'Domain Name System' },
            80: { service: 'HTTP', risk: 'warning', description: 'Unverschlüsselter Webserver' },
            110: { service: 'POP3', risk: 'warning', description: 'Post Office Protocol - oft unverschlüsselt' },
            111: { service: 'RPCBind', risk: 'critical', description: 'RPC Portmapper - Sicherheitsrisiko' },
            135: { service: 'MSRPC', risk: 'critical', description: 'Microsoft RPC - häufiges Angriffsziel' },
            139: { service: 'NetBIOS', risk: 'critical', description: 'NetBIOS Session Service' },
            143: { service: 'IMAP', risk: 'warning', description: 'Internet Message Access Protocol' },
            443: { service: 'HTTPS', risk: 'safe', description: 'Verschlüsselter Webserver' },
            445: { service: 'SMB', risk: 'critical', description: 'Server Message Block - häufiges Angriffsziel' },
            993: { service: 'IMAPS', risk: 'safe', description: 'IMAP über SSL' },
            995: { service: 'POP3S', risk: 'safe', description: 'POP3 über SSL' },
            1433: { service: 'MSSQL', risk: 'critical', description: 'Microsoft SQL Server' },
            1521: { service: 'Oracle', risk: 'critical', description: 'Oracle Database' },
            3306: { service: 'MySQL', risk: 'critical', description: 'MySQL Database' },
            3389: { service: 'RDP', risk: 'critical', description: 'Remote Desktop Protocol' },
            5432: { service: 'PostgreSQL', risk: 'critical', description: 'PostgreSQL Database' },
            5900: { service: 'VNC', risk: 'critical', description: 'Virtual Network Computing' },
            6379: { service: 'Redis', risk: 'critical', description: 'Redis Database' },
            8080: { service: 'HTTP-Alt', risk: 'warning', description: 'Alternativer HTTP Port' },
            8443: { service: 'HTTPS-Alt', risk: 'warning', description: 'Alternativer HTTPS Port' },
            27017: { service: 'MongoDB', risk: 'critical', description: 'MongoDB Database' }
        };
    }

    // Top 100 ports for quick scan
    static get TOP_100_PORTS() {
        return '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157';
    }

    // Top 1000 ports for standard scan
    static get TOP_1000_PORTS() {
        return '1-1024,1025-1030,1080,1099,1110,1194,1433,1434,1521,1604,1723,1755,1900,2000,2001,2049,2082,2083,2086,2087,2095,2096,2121,2181,2222,2375,2376,2717,3000,3128,3268,3269,3306,3389,3690,3986,4443,4444,4567,4711,4712,4848,4899,5000,5001,5009,5050,5051,5060,5061,5101,5190,5222,5223,5357,5432,5555,5601,5631,5632,5666,5672,5800,5900,5901,5984,5985,5986,6000,6001,6379,6443,6646,6660,6661,6662,6663,6664,6665,6666,6667,6668,6669,7000,7001,7002,7070,7071,7077,7078,7474,7547,7548,8000,8001,8008,8009,8010,8020,8042,8060,8069,8080,8081,8082,8083,8088,8090,8091,8139,8140,8161,8200,8222,8333,8334,8443,8444,8500,8649,8834,8880,8888,8889,8983,9000,9001,9002,9042,9043,9060,9080,9090,9091,9100,9200,9300,9418,9443,9876,9990,9999,10000,10001,10050,10051,10250,10443,11211,11300,12345,13579,14147,16010,16080,18080,19888,20000,20547,21025,22222,23023,25565,27017,27018,28017,30000,32400,32768,33060,37777,40000,44443,47001,48899,49152,49153,49154,49155,49156,49157,50000,50070,54321,55553,55555,60000,60010,60030,61616,63790,64738';
    }

    // Validate IP address
    static isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        return ipv4Regex.test(ip);
    }

    // Validate CIDR notation
    static isValidCIDR(cidr) {
        try {
            const ipCidr = new IPCIDR(cidr);
            return ipCidr.isValid();
        } catch {
            return false;
        }
    }

    // Check if IP is in private range (RFC 1918)
    static isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        // 10.0.0.0/8
        if (parts[0] === 10) return true;
        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168) return true;
        // 127.0.0.0/8 (loopback)
        if (parts[0] === 127) return true;
        return false;
    }

    // Validate target (IP or CIDR)
    static validateTarget(target) {
        const trimmed = target.trim();

        // Check if it's a CIDR range
        if (trimmed.includes('/')) {
            if (!ScannerService.isValidCIDR(trimmed)) {
                return { valid: false, error: 'Ungültiger CIDR-Bereich' };
            }
            // Check CIDR size - limit to /24 to prevent huge scans
            const prefix = parseInt(trimmed.split('/')[1]);
            if (prefix < 24) {
                return { valid: false, error: 'CIDR-Bereich zu groß. Maximal /24 (256 Adressen) erlaubt.' };
            }
            return { valid: true, type: 'cidr', target: trimmed };
        }

        // Single IP
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
            case 'quick':
                return ScannerService.TOP_100_PORTS;
            case 'standard':
                return ScannerService.TOP_1000_PORTS;
            case 'full':
                return '1-65535';
            case 'custom':
                return customPorts;
            default:
                return ScannerService.TOP_100_PORTS;
        }
    }

    // Get risk level for a port
    static getRiskLevel(port, state) {
        if (state !== 'open') return 'info';
        const portInfo = ScannerService.CRITICAL_PORTS[port];
        if (portInfo) return portInfo.risk;
        return 'warning'; // Unknown open ports are warnings by default
    }

    // Get service name for a port
    static getServiceName(port) {
        const portInfo = ScannerService.CRITICAL_PORTS[port];
        return portInfo ? portInfo.service : 'Unknown';
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
        this._executeScan(scanId, targetValidation, portRange);

        return {
            id: scanId,
            status: 'running',
            scanType,
            target,
            portRange
        };
    }

    // Internal: Execute the scan
    async _executeScan(scanId, targetValidation, portRange) {
        const db = getDatabase();
        const results = [];
        let scanControl = { aborted: false };
        this.activeScans.set(scanId, scanControl);

        // Set timeout
        const timeoutHandle = setTimeout(() => {
            this.stopScan(scanId);
            logger.warn(`Scan ${scanId} timed out after ${this.SCAN_TIMEOUT}ms`);
        }, this.SCAN_TIMEOUT);

        try {
            let targets = [];
            if (targetValidation.type === 'cidr') {
                targets = ScannerService.expandCIDR(targetValidation.target);
            } else {
                targets = [targetValidation.target];
            }

            const totalTargets = targets.length;
            let completedTargets = 0;

            for (const ip of targets) {
                if (scanControl.aborted) {
                    logger.info(`Scan ${scanId} was aborted`);
                    break;
                }

                try {
                    const scanResults = await this._scanHost(ip, portRange, scanControl);
                    results.push(...scanResults);

                    // Save results to database incrementally
                    const insertStmt = db.prepare(
                        'INSERT INTO scan_results (scan_id, ip_address, port, protocol, service, state, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?)'
                    );

                    const insertMany = db.transaction((items) => {
                        for (const item of items) {
                            insertStmt.run(
                                scanId,
                                item.ip,
                                item.port,
                                item.protocol || 'tcp',
                                item.service,
                                item.state,
                                item.riskLevel
                            );
                        }
                    });

                    if (scanResults.length > 0) {
                        insertMany(scanResults);
                    }
                } catch (hostErr) {
                    logger.error(`Error scanning host ${ip} in scan ${scanId}:`, hostErr);
                }

                completedTargets++;
                const progress = Math.round((completedTargets / totalTargets) * 100);

                // Update progress
                db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, scanId);
                this.emit('scanProgress', { scanId, progress, completedTargets, totalTargets });
            }

            // Mark scan as completed
            const finalStatus = scanControl.aborted ? 'aborted' : 'completed';
            db.prepare(
                'UPDATE scans SET status = ?, progress = 100, completed_at = CURRENT_TIMESTAMP WHERE id = ?'
            ).run(finalStatus, scanId);

            this.emit('scanComplete', { scanId, status: finalStatus, resultCount: results.length });
            logger.info(`Scan ${scanId} ${finalStatus} with ${results.length} results`);
            logger.audit('SCAN_COMPLETED', { scanId, status: finalStatus, resultCount: results.length });

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

    // Internal: Scan a single host
    _scanHost(ip, portRange, scanControl) {
        return new Promise((resolve, reject) => {
            const results = [];

            // Parse port range for evilscan
            // evilscan expects format like "21-443" or "80" or "21,22,80,443"
            const options = {
                target: ip,
                port: portRange,
                status: 'O', // Only open ports
                timeout: 2000,
                concurrency: 100,
                geo: false
            };

            try {
                const scanner = new evilscan(options);

                scanner.on('result', (data) => {
                    if (scanControl.aborted) {
                        scanner.abort();
                        return;
                    }

                    // evilscan returns status as text: "open", "closed (refused)", "closed (timeout)", etc.
                    const statusLower = (data.status || '').toLowerCase();
                    if (statusLower === 'open' || statusLower === 'o') {
                        const port = data.port;
                        const service = ScannerService.getServiceName(port);
                        const riskLevel = ScannerService.getRiskLevel(port, 'open');

                        results.push({
                            ip: data.ip || ip,
                            port: port,
                            protocol: 'tcp',
                            service: service,
                            state: 'open',
                            riskLevel: riskLevel
                        });
                    }
                });

                scanner.on('error', (err) => {
                    logger.error(`Scan error for ${ip}: ${err}`);
                    // Don't reject - continue with partial results
                });

                scanner.on('done', () => {
                    resolve(results);
                });

                // Store scanner reference for abort capability
                if (scanControl) {
                    scanControl.scanner = scanner;
                }

                scanner.run();
            } catch (err) {
                logger.error(`Failed to initialize scan for ${ip}:`, err);
                resolve(results); // Return empty results instead of failing
            }
        });
    }

    // Stop a running scan
    stopScan(scanId) {
        const scanControl = this.activeScans.get(scanId);
        if (scanControl) {
            scanControl.aborted = true;
            if (scanControl.scanner && typeof scanControl.scanner.abort === 'function') {
                scanControl.scanner.abort();
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
                page,
                limit,
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

        if (filters.dateFrom) {
            query += ' AND s.started_at >= ?';
            params.push(filters.dateFrom);
        }
        if (filters.dateTo) {
            query += ' AND s.started_at <= ?';
            params.push(filters.dateTo);
        }
        if (filters.scanType) {
            query += ' AND s.scan_type = ?';
            params.push(filters.scanType);
        }
        if (filters.target) {
            query += ' AND s.target LIKE ?';
            params.push(`%${filters.target}%`);
        }
        if (filters.status) {
            query += ' AND s.status = ?';
            params.push(filters.status);
        }

        query += ' GROUP BY s.id ORDER BY s.started_at DESC';

        // Pagination
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
                page,
                limit,
                total: total.count,
                totalPages: Math.ceil(total.count / limit)
            }
        };
    }

    // Compare two scans
    compareScans(scanId1, scanId2) {
        const db = getDatabase();

        const results1 = db.prepare(
            'SELECT ip_address, port, protocol, service, state, risk_level FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port'
        ).all(scanId1);

        const results2 = db.prepare(
            'SELECT ip_address, port, protocol, service, state, risk_level FROM scan_results WHERE scan_id = ? ORDER BY ip_address, port'
        ).all(scanId2);

        const scan1 = this.getScanStatus(scanId1);
        const scan2 = this.getScanStatus(scanId2);

        // Create sets for comparison
        const set1 = new Set(results1.map(r => `${r.ip_address}:${r.port}`));
        const set2 = new Set(results2.map(r => `${r.ip_address}:${r.port}`));

        const onlyInScan1 = results1.filter(r => !set2.has(`${r.ip_address}:${r.port}`));
        const onlyInScan2 = results2.filter(r => !set1.has(`${r.ip_address}:${r.port}`));
        const inBoth = results1.filter(r => set2.has(`${r.ip_address}:${r.port}`));

        return {
            scan1: { info: scan1, resultCount: results1.length },
            scan2: { info: scan2, resultCount: results2.length },
            comparison: {
                onlyInScan1,
                onlyInScan2,
                inBoth,
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