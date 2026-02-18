const { getDatabase } = require('../config/database');
const logger = require('./logger');
const FingerprintService = require('./fingerprintService');
const ExploitService = require('./exploitService');

class AttackChainService {

    // Strategy depth configurations
    static get STRATEGIES() {
        return {
            passive: { maxDepth: 1, description: 'Nur Reconnaissance – keine aktiven Tests', allowedTypes: ['recon'] },
            standard: { maxDepth: 2, description: 'Reconnaissance + Konfigurationsaudit', allowedTypes: ['recon', 'audit', 'enum', 'auth_test'] },
            aggressive: { maxDepth: 3, description: 'Vollständige Analyse inkl. Exploit-Matching', allowedTypes: ['recon', 'audit', 'enum', 'auth_test', 'vuln_scan', 'exploit'] },
            thorough: { maxDepth: 4, description: 'Tiefenanalyse mit allen verfügbaren Methoden', allowedTypes: ['recon', 'audit', 'enum', 'auth_test', 'vuln_scan', 'exploit', 'post_exploit'] }
        };
    }

    // Get all attack chains
    static getAll(filters = {}) {
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
    static getById(id) {
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
    static findApplicableChains(scanId) {
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
    static executeChain(scanId, chainId, targetIp, targetPort, userId) {
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
        const results = [];
        let currentStep = 0;

        try {
            for (const step of steps) {
                currentStep++;
                const stepResult = this._executeStep(step, scanId, targetIp, targetPort, chain);

                results.push({
                    step: currentStep,
                    name: step.name,
                    type: step.type,
                    status: stepResult.success ? 'completed' : 'failed',
                    findings: stepResult.findings || [],
                    details: stepResult.details || '',
                    timestamp: new Date().toISOString()
                });

                // Update progress
                db.prepare('UPDATE attack_chain_executions SET current_step = ?, results_json = ? WHERE id = ?')
                    .run(currentStep, JSON.stringify(results), executionId);
            }

            // Collect all findings
            const allFindings = results.flatMap(r => r.findings);

            // Mark as completed
            db.prepare(`
                UPDATE attack_chain_executions 
                SET status = 'completed', current_step = ?, results_json = ?, findings_json = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(currentStep, JSON.stringify(results), JSON.stringify(allFindings), executionId);

            logger.info(`Attack chain ${chainId} completed for ${targetIp}:${targetPort} - ${allFindings.length} findings`);
            logger.audit('ATTACK_CHAIN_COMPLETED', { executionId, chainId, targetIp, targetPort, findingsCount: allFindings.length });

            return {
                executionId,
                chainName: chain.name,
                status: 'completed',
                stepsCompleted: currentStep,
                totalSteps: steps.length,
                results,
                findings: allFindings
            };

        } catch (err) {
            db.prepare(`
                UPDATE attack_chain_executions 
                SET status = 'failed', results_json = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(JSON.stringify(results), executionId);

            logger.error(`Attack chain ${chainId} failed for ${targetIp}:`, err);
            throw err;
        }
    }

    // Execute a single step of an attack chain
    static _executeStep(step, scanId, targetIp, targetPort, chain) {
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
                const portInfo = require('./scanner').constructor.CRITICAL_PORTS[targetPort];
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
                    SELECT v.* FROM scan_vulnerabilities sv
                    JOIN vulnerabilities v ON sv.vulnerability_id = v.id
                    JOIN scan_results sr ON sv.scan_result_id = sr.id
                    WHERE sv.scan_id = ? AND sr.ip_address = ? AND sr.port = ?
                `).all(scanId, targetIp, targetPort);

                for (const vuln of vulns) {
                    findings.push({
                        type: 'vulnerability',
                        category: 'Schwachstelle',
                        title: `${vuln.cve_id || 'N/A'}: ${vuln.title}`,
                        details: vuln.description,
                        severity: vuln.severity,
                        cvss: vuln.cvss_score,
                        remediation: vuln.remediation
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

                for (const exploit of exploits) {
                    findings.push({
                        type: 'exploit',
                        category: 'Exploit verfügbar',
                        title: `${exploit.cve_id || exploit.exploit_db_id}: ${exploit.title}`,
                        details: `Plattform: ${exploit.platform}, Typ: ${exploit.exploit_type}, Zuverlässigkeit: ${exploit.reliability}, Confidence: ${exploit.match_confidence}%`,
                        severity: exploit.severity,
                        cvss: exploit.cvss_score,
                        sourceUrl: exploit.source_url,
                        remediation: `Patch für ${exploit.cve_id || 'diese Schwachstelle'} installieren`
                    });
                }
                return { success: true, findings, details: `${exploits.length} Exploits zugeordnet` };
            }

            default:
                return { success: true, findings: [], details: `Schritt-Typ '${step.type}' übersprungen` };
        }
    }

    // Get execution history for a scan
    static getExecutions(scanId) {
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
    static getExecutionById(executionId) {
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
    static create(data, userId) {
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
    static toggleEnabled(id) {
        const db = getDatabase();
        const chain = db.prepare('SELECT enabled FROM attack_chains WHERE id = ?').get(id);
        if (!chain) throw new Error('Attack Chain nicht gefunden');
        const newState = chain.enabled ? 0 : 1;
        db.prepare('UPDATE attack_chains SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newState, id);
        return newState === 1;
    }

    // Delete a chain
    static delete(id) {
        const db = getDatabase();
        db.prepare('DELETE FROM attack_chains WHERE id = ?').run(id);
        logger.info(`Attack chain deleted: ID ${id}`);
    }

    // Get available strategies
    static getStrategies() {
        return Object.entries(this.STRATEGIES).map(([key, val]) => ({
            id: key,
            ...val
        }));
    }
}

module.exports = AttackChainService;