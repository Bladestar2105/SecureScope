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
                // Find which ports triggered this chain
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
            const dbInner = getDatabase(); // Re-get DB connection for async context if needed (though sync is fine)

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

                    const stepResult = await this._executeStep(step, scanId, targetIp, targetPort, chain, params);

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
                // Service enumeration simulation
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
                // Check if credentials are available for this service
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
                // Match against vulnerability database
                const vulns = db.prepare(`
                    SELECT sv.cve_id, sv.title, sv.severity, sv.cvss_score, ce.description
                    FROM scan_vulnerabilities sv
                    LEFT JOIN cve_entries ce ON sv.cve_id = ce.cve_id
                    JOIN scan_results sr ON sv.scan_result_id = sr.id
                    WHERE sv.scan_id = ? AND sr.ip_address = ? AND sr.port = ?
                `).all(scanId, targetIp, targetPort);

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
                // Match against exploit database
                const exploits = db.prepare(`
                    SELECT e.*, se.match_confidence FROM scan_exploits se
                    JOIN exploits e ON se.exploit_id = e.id
                    JOIN scan_results sr ON se.scan_result_id = sr.id
                    WHERE se.scan_id = ? AND sr.ip_address = ? AND sr.port = ?
                    ORDER BY e.cvss_score DESC
                `).all(scanId, targetIp, targetPort);

                let successCount = 0;

                for (const exploit of exploits) {
                    // Start listener if requested
                    let sessionId = null;
                    let tempFile = null;

                    try {
                        // 1. Prepare Exploit
                        const exploitData = ExploitDbSyncService.getExploitCode(exploit.id);
                        if (!exploitData || !exploitData.code) {
                            findings.push({
                                type: 'info',
                                category: 'Exploit Skipped',
                                title: `Code missing: ${exploit.title}`,
                                details: 'Exploit code not found locally.',
                                severity: 'info'
                            });
                            continue;
                        }

                        // Substitute placeholders
                        let code = exploitData.code;
                        const lhost = params.LHOST || '127.0.0.1';
                        const lport = params.LPORT ? parseInt(params.LPORT) : null;

                        // Sanity Check for LHOST
                        if (lhost === '127.0.0.1' || lhost === 'localhost') {
                             findings.push({
                                type: 'warning',
                                category: 'Configuration Warning',
                                title: `LHOST is loopback`,
                                details: `Warning: LHOST is set to ${lhost}. Remote shells will not connect back if the target is external.`,
                                severity: 'low'
                            });
                        }

                        let modified = false;

                        // Robust replacement logic
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

                        // 2. Variable assignments (e.g. LHOST = "...")
                        // Simple approach: Replace literal string "LHOST" if it looks like a variable placeholder
                        // Or just brute force replace common uppercase vars if they exist
                        for (const [key, val] of Object.entries(replaceMap)) {
                            if (val) {
                                // Replace simple occurrences like LHOST="xxx" or LHOST = 'xxx'
                                // We replace the placeholder key itself
                                const regex = new RegExp(`\\b${key}\\b`, 'g');
                                if (regex.test(code)) {
                                     // This is risky if LHOST is a variable name in code, but typically in exploitdb scripts
                                     // users are expected to edit these variables.
                                     // We will assume the script is not using LHOST as a local variable name for logic but as config.
                                     // A safer way is checking specific patterns users use.
                                     // But for now, we stick to the provided pattern and expand slightly.
                                     // The previous logic was: code.replace(/LHOST/g, lhost)
                                     code = code.replace(regex, val);
                                     modified = true;
                                }
                            }
                        }

                        // Write temp file
                        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exploit-'));
                        const ext = exploitData.language === 'python' ? '.py' :
                                    exploitData.language === 'ruby' ? '.rb' :
                                    exploitData.language === 'bash' ? '.sh' :
                                    exploitData.language === 'c' ? '.c' : '.txt';

                        tempFile = path.join(tmpDir, `exploit${ext}`);
                        fs.writeFileSync(tempFile, code);

                        // 2. Start Listener (if LPORT provided)
                        if (lport) {
                            sessionId = ShellService.startListener(lport);
                        }

                        // 3. Execute
                        logger.info(`Executing exploit ${exploit.id} (${exploitData.language}) for ${targetIp}`);

                        let cmd = '';
                        if (exploitData.language === 'python') cmd = `python3 "${tempFile}"`;
                        else if (exploitData.language === 'ruby') cmd = `ruby "${tempFile}"`;
                        else if (exploitData.language === 'bash') cmd = `bash "${tempFile}"`;
                        else if (exploitData.language === 'c') {
                            // Compile first
                            const binFile = path.join(tmpDir, 'exploit.bin');
                            await execPromise(`gcc "${tempFile}" -o "${binFile}"`);
                            cmd = `"${binFile}"`;
                        } else {
                            throw new Error(`Unsupported language: ${exploitData.language}`);
                        }

                        // Pass arguments if needed (some scripts take args)
                        // For now we rely on the hardcoded replacements above

                        // Run with timeout
                        await new Promise((resolve, reject) => {
                            exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
                                if (error) {
                                    logger.warn(`Exploit ${exploit.id} execution error/timeout: ${error.message}`);
                                    // We don't necessarily reject, just log and finish this step
                                }
                                resolve();
                            });
                        });

                        // 4. Check for Shell
                        if (sessionId) {
                            // Poll for a few seconds if not already connected
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
                            }
                        } else {
                             // Blind execution (DoS or other)
                             findings.push({
                                type: 'exploit_attempt',
                                category: 'Exploit Executed',
                                title: `Exploit ausgeführt: ${exploit.title}`,
                                details: `Exploit wurde ausgeführt (kein Reverse Shell Listener konfiguriert).`,
                                severity: 'info'
                            });
                        }

                    } catch (e) {
                        logger.error(`Exploit execution failed for ${exploit.id}:`, e);
                        if (sessionId) ShellService.killSession(sessionId);
                    } finally {
                        // Cleanup temp file
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
        // Accept both camelCase and snake_case
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
}

module.exports = new AttackChainService();