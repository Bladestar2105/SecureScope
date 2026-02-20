const { getDatabase } = require('../config/database');
const logger = require('./logger');
const VulnerabilityService = require('./vulnerabilityService');
const FingerprintService = require('./fingerprintService');
const ExploitService = require('./exploitService');
const attackChainService = require('./attackChainService');

class SecurityAuditService {

    // Risk rating thresholds
    static get RISK_THRESHOLDS() {
        return {
            critical: { min: 0, max: 25, label: 'Kritisch', color: '#ef4444', description: 'Sofortige Maßnahmen erforderlich' },
            high: { min: 25, max: 50, label: 'Hoch', color: '#f59e0b', description: 'Dringende Maßnahmen empfohlen' },
            medium: { min: 50, max: 75, label: 'Mittel', color: '#3b82f6', description: 'Verbesserungen empfohlen' },
            low: { min: 75, max: 90, label: 'Niedrig', color: '#22c55e', description: 'Geringes Risiko, Optimierungen möglich' },
            secure: { min: 90, max: 100, label: 'Sicher', color: '#10b981', description: 'Guter Sicherheitsstatus' }
        };
    }

    // Generate a full security audit for a scan
    static generateAudit(scanId, userId) {
        const db = getDatabase();

        // Verify scan exists and is completed
        const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
        if (!scan) throw new Error('Scan nicht gefunden');
        if (scan.status !== 'completed') throw new Error('Scan muss abgeschlossen sein für ein Audit');

        // Gather all data
        const scanResults = db.prepare("SELECT * FROM scan_results WHERE scan_id = ? AND state = 'open'").all(scanId);
        const vulnSummary = VulnerabilityService.getScanVulnerabilitySummary(scanId);
        const vulns = VulnerabilityService.getScanVulnerabilities(scanId);
        const fingerprints = FingerprintService.getScanFingerprints(scanId);
        const exploitSummary = ExploitService.getScanExploitSummary(scanId);
        const exploits = ExploitService.getScanExploits(scanId);
        const chainExecutions = attackChainService.getExecutions(scanId);

        // Calculate security score
        const scoreData = this._calculateScore(scanResults, vulns, exploits, fingerprints);

        // Generate findings
        const findings = this._generateFindings(scanResults, vulns, exploits, fingerprints, chainExecutions);

        // Generate recommendations
        const recommendations = this._generateRecommendations(findings, scanResults, fingerprints);

        // Generate compliance check
        const compliance = this._checkCompliance(scanResults, vulns, fingerprints);

        // Generate executive summary
        const summary = this._generateSummary(scan, scoreData, findings, recommendations);

        // Count findings by severity
        const findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const f of findings) {
            if (findingCounts[f.severity] !== undefined) findingCounts[f.severity]++;
        }

        // Create audit record
        const auditResult = db.prepare(`
            INSERT INTO security_audits (scan_id, audit_type, overall_score, risk_rating, executive_summary,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                recommendations_json, compliance_json, generated_by)
            VALUES (?, 'full', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            scanId, scoreData.score, scoreData.rating, summary,
            findings.length, findingCounts.critical, findingCounts.high,
            findingCounts.medium, findingCounts.low, findingCounts.info,
            JSON.stringify(recommendations), JSON.stringify(compliance), userId
        );

        const auditId = auditResult.lastInsertRowid;

        // Insert findings
        const findingStmt = db.prepare(`
            INSERT INTO audit_findings (audit_id, category, title, description, severity, cvss_score,
                affected_asset, affected_port, affected_service, evidence, remediation, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        const insertFindings = db.transaction((items) => {
            for (const f of items) {
                findingStmt.run(
                    auditId, f.category, f.title, f.description, f.severity,
                    f.cvss || null, f.asset || null, f.port || null, f.service || null,
                    f.evidence || null, f.remediation || null, f.priority || 3
                );
            }
        });

        insertFindings(findings);

        logger.info(`Security audit generated for scan ${scanId}: Score ${scoreData.score}, Rating: ${scoreData.rating}, Findings: ${findings.length}`);
        logger.audit('AUDIT_GENERATED', { auditId, scanId, score: scoreData.score, findingsCount: findings.length });

        return {
            id: auditId,
            scanId,
            score: scoreData.score,
            rating: scoreData.rating,
            ratingInfo: this.RISK_THRESHOLDS[scoreData.rating],
            summary,
            findings,
            findingCounts,
            recommendations,
            compliance
        };
    }

    // Calculate overall security score (0-100, higher = more secure)
    static _calculateScore(scanResults, vulns, exploits, fingerprints) {
        let score = 100;
        let deductions = [];

        // Deduct for open ports
        const criticalPorts = scanResults.filter(r => r.risk_level === 'critical');
        const warningPorts = scanResults.filter(r => r.risk_level === 'warning');

        score -= criticalPorts.length * 5;
        deductions.push({ reason: `${criticalPorts.length} kritische Ports offen`, points: criticalPorts.length * 5 });

        score -= warningPorts.length * 2;
        deductions.push({ reason: `${warningPorts.length} Ports mit Warnung`, points: warningPorts.length * 2 });

        // Deduct for vulnerabilities
        const critVulns = vulns.filter(v => v.severity === 'critical');
        const highVulns = vulns.filter(v => v.severity === 'high');
        const medVulns = vulns.filter(v => v.severity === 'medium');

        score -= critVulns.length * 10;
        deductions.push({ reason: `${critVulns.length} kritische Schwachstellen`, points: critVulns.length * 10 });

        score -= highVulns.length * 5;
        deductions.push({ reason: `${highVulns.length} hohe Schwachstellen`, points: highVulns.length * 5 });

        score -= medVulns.length * 2;
        deductions.push({ reason: `${medVulns.length} mittlere Schwachstellen`, points: medVulns.length * 2 });

        // Deduct for available exploits
        const critExploits = exploits.filter(e => e.severity === 'critical');
        score -= critExploits.length * 8;
        deductions.push({ reason: `${critExploits.length} kritische Exploits verfügbar`, points: critExploits.length * 8 });

        // Deduct for unencrypted services
        const unencrypted = fingerprints.filter(f => {
            const svc = (f.detected_service || '').toLowerCase();
            return ['ftp', 'telnet', 'http', 'pop3'].some(u => svc.includes(u)) && !svc.includes('ssl') && !svc.includes('tls');
        });
        score -= unencrypted.length * 3;
        deductions.push({ reason: `${unencrypted.length} unverschlüsselte Dienste`, points: unencrypted.length * 3 });

        // Ensure score is between 0 and 100
        score = Math.max(0, Math.min(100, score));

        // Determine rating
        let rating = 'secure';
        for (const [key, threshold] of Object.entries(this.RISK_THRESHOLDS)) {
            if (score >= threshold.min && score < threshold.max) {
                rating = key;
                break;
            }
        }
        if (score >= 90) rating = 'secure';

        return { score: Math.round(score * 10) / 10, rating, deductions };
    }

    // Generate detailed findings
    static _generateFindings(scanResults, vulns, exploits, fingerprints, chainExecutions) {
        const findings = [];
        let priority = 0;

        // Critical open ports
        for (const result of scanResults) {
            if (result.risk_level === 'critical') {
                priority++;
                findings.push({
                    category: 'Netzwerk',
                    title: `Kritischer Port ${result.port} (${result.service}) offen`,
                    description: `Der Port ${result.port} (${result.service}) auf ${result.ip_address} ist offen und stellt ein erhöhtes Sicherheitsrisiko dar.`,
                    severity: 'high',
                    port: result.port,
                    service: result.service,
                    asset: result.ip_address,
                    evidence: `Port-Scan: ${result.ip_address}:${result.port} - Status: ${result.state}`,
                    remediation: `Prüfen Sie, ob Port ${result.port} (${result.service}) benötigt wird. Falls nicht, schließen Sie den Port per Firewall.`,
                    priority: Math.min(priority, 5)
                });
            }
        }

        // Vulnerabilities
        for (const vuln of vulns) {
            priority++;
            findings.push({
                category: 'Schwachstelle',
                title: `${vuln.cve_id || 'N/A'}: ${vuln.title}`,
                description: vuln.description,
                severity: vuln.severity,
                cvss: vuln.cvss_score,
                port: vuln.port,
                service: vuln.service,
                asset: vuln.ip_address,
                evidence: `CVE: ${vuln.cve_id}, CVSS: ${vuln.cvss_score}, Port: ${vuln.port}`,
                remediation: vuln.remediation,
                priority: vuln.severity === 'critical' ? 1 : vuln.severity === 'high' ? 2 : 3
            });
        }

        // Exploits
        for (const exploit of exploits) {
            // Avoid duplicate findings for same CVE
            if (exploit.cve_id && findings.some(f => f.title.includes(exploit.cve_id))) continue;

            findings.push({
                category: 'Exploit',
                title: `Exploit verfügbar: ${exploit.exploit_title}`,
                description: `Für ${exploit.ip_address}:${exploit.port} existiert ein bekannter Exploit (${exploit.cve_id || exploit.exploit_db_id}). Zuverlässigkeit: ${exploit.reliability}, Confidence: ${exploit.match_confidence}%`,
                severity: exploit.severity,
                cvss: exploit.cvss_score,
                port: exploit.port,
                service: exploit.service,
                asset: exploit.ip_address,
                evidence: `Exploit-DB: ${exploit.exploit_db_id || 'N/A'}, Quelle: ${exploit.source_url || 'N/A'}`,
                remediation: `Patch für ${exploit.cve_id || 'diese Schwachstelle'} umgehend installieren.`,
                priority: exploit.severity === 'critical' ? 1 : 2
            });
        }

        // Findings from attack chain executions
        for (const exec of chainExecutions) {
            for (const finding of exec.findings) {
                if (finding.severity !== 'info') {
                    findings.push({
                        category: finding.category || 'Angriffskette',
                        title: finding.title,
                        description: finding.details,
                        severity: finding.severity,
                        cvss: finding.cvss || null,
                        asset: exec.target_ip,
                        port: exec.target_port,
                        remediation: finding.remediation || null,
                        priority: finding.severity === 'critical' ? 1 : finding.severity === 'high' ? 2 : 3
                    });
                }
            }
        }

        // Sort by priority then severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        findings.sort((a, b) => {
            if (a.priority !== b.priority) return a.priority - b.priority;
            return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
        });

        return findings;
    }

    // Generate recommendations
    static _generateRecommendations(findings, scanResults, fingerprints) {
        const recommendations = [];
        const addedCategories = new Set();

        // Check for critical findings
        const criticalFindings = findings.filter(f => f.severity === 'critical');
        if (criticalFindings.length > 0 && !addedCategories.has('critical_patch')) {
            addedCategories.add('critical_patch');
            recommendations.push({
                priority: 1,
                category: 'Patch-Management',
                title: 'Kritische Sicherheitsupdates installieren',
                description: `Es wurden ${criticalFindings.length} kritische Schwachstellen gefunden. Installieren Sie umgehend alle verfügbaren Sicherheitspatches.`,
                effort: 'mittel',
                impact: 'hoch'
            });
        }

        // Check for unencrypted services
        const unencryptedPorts = scanResults.filter(r => [21, 23, 80, 110, 143].includes(r.port));
        if (unencryptedPorts.length > 0 && !addedCategories.has('encryption')) {
            addedCategories.add('encryption');
            recommendations.push({
                priority: 2,
                category: 'Verschlüsselung',
                title: 'Unverschlüsselte Dienste migrieren',
                description: `${unencryptedPorts.length} Dienste übertragen Daten unverschlüsselt. Migrieren Sie zu verschlüsselten Alternativen (SFTP, SSH, HTTPS, IMAPS).`,
                effort: 'mittel',
                impact: 'hoch'
            });
        }

        // Check for exposed databases
        const dbPorts = scanResults.filter(r => [1433, 3306, 5432, 6379, 27017].includes(r.port));
        if (dbPorts.length > 0 && !addedCategories.has('db_exposure')) {
            addedCategories.add('db_exposure');
            recommendations.push({
                priority: 1,
                category: 'Netzwerk-Segmentierung',
                title: 'Datenbank-Zugriff einschränken',
                description: `${dbPorts.length} Datenbank-Dienste sind direkt erreichbar. Beschränken Sie den Zugriff per Firewall auf autorisierte Systeme.`,
                effort: 'niedrig',
                impact: 'hoch'
            });
        }

        // Check for remote access services
        const remotePorts = scanResults.filter(r => [3389, 5900, 22].includes(r.port));
        if (remotePorts.length > 0 && !addedCategories.has('remote_access')) {
            addedCategories.add('remote_access');
            recommendations.push({
                priority: 2,
                category: 'Zugriffskontrolle',
                title: 'Remote-Zugriff absichern',
                description: 'Verwenden Sie VPN für Remote-Zugriffe. Aktivieren Sie Multi-Faktor-Authentifizierung und beschränken Sie den Zugriff auf autorisierte IP-Adressen.',
                effort: 'mittel',
                impact: 'hoch'
            });
        }

        // General firewall recommendation
        const totalOpen = scanResults.length;
        if (totalOpen > 10 && !addedCategories.has('firewall')) {
            addedCategories.add('firewall');
            recommendations.push({
                priority: 2,
                category: 'Firewall',
                title: 'Firewall-Regeln überprüfen',
                description: `${totalOpen} offene Ports gefunden. Überprüfen Sie die Firewall-Konfiguration und schließen Sie nicht benötigte Ports.`,
                effort: 'niedrig',
                impact: 'mittel'
            });
        }

        // Network segmentation
        if (totalOpen > 5 && !addedCategories.has('segmentation')) {
            addedCategories.add('segmentation');
            recommendations.push({
                priority: 3,
                category: 'Netzwerk',
                title: 'Netzwerk-Segmentierung implementieren',
                description: 'Trennen Sie kritische Systeme in separate Netzwerksegmente. Verwenden Sie VLANs und Firewall-Zonen.',
                effort: 'hoch',
                impact: 'hoch'
            });
        }

        // Monitoring recommendation
        if (!addedCategories.has('monitoring')) {
            addedCategories.add('monitoring');
            recommendations.push({
                priority: 3,
                category: 'Monitoring',
                title: 'Sicherheitsüberwachung einrichten',
                description: 'Implementieren Sie ein SIEM-System und konfigurieren Sie Alarme für verdächtige Aktivitäten. Führen Sie regelmäßige Scans durch.',
                effort: 'hoch',
                impact: 'mittel'
            });
        }

        recommendations.sort((a, b) => a.priority - b.priority);
        return recommendations;
    }

    // Check compliance against common standards
    static _checkCompliance(scanResults, vulns, fingerprints) {
        const checks = {
            encryption: {
                name: 'Verschlüsselung',
                description: 'Alle Dienste verwenden Verschlüsselung',
                status: 'pass',
                details: []
            },
            patchLevel: {
                name: 'Patch-Level',
                description: 'Keine bekannten kritischen Schwachstellen',
                status: 'pass',
                details: []
            },
            accessControl: {
                name: 'Zugriffskontrolle',
                description: 'Keine ungeschützten Dienste exponiert',
                status: 'pass',
                details: []
            },
            networkSecurity: {
                name: 'Netzwerksicherheit',
                description: 'Minimale Angriffsfläche',
                status: 'pass',
                details: []
            }
        };

        // Check encryption
        const unencrypted = scanResults.filter(r => [21, 23, 80, 110, 143].includes(r.port));
        if (unencrypted.length > 0) {
            checks.encryption.status = 'fail';
            checks.encryption.details = unencrypted.map(r => `Port ${r.port} (${r.service}) unverschlüsselt`);
        }

        // Check patch level
        const critVulns = vulns.filter(v => v.severity === 'critical');
        if (critVulns.length > 0) {
            checks.patchLevel.status = 'fail';
            checks.patchLevel.details = critVulns.map(v => `${v.cve_id}: ${v.title}`);
        } else if (vulns.filter(v => v.severity === 'high').length > 0) {
            checks.patchLevel.status = 'warning';
            checks.patchLevel.details = vulns.filter(v => v.severity === 'high').map(v => `${v.cve_id}: ${v.title}`);
        }

        // Check access control
        const exposedDB = scanResults.filter(r => [1433, 3306, 5432, 6379, 27017].includes(r.port));
        const exposedRemote = scanResults.filter(r => [3389, 5900].includes(r.port));
        if (exposedDB.length > 0 || exposedRemote.length > 0) {
            checks.accessControl.status = exposedDB.length > 0 ? 'fail' : 'warning';
            checks.accessControl.details = [
                ...exposedDB.map(r => `Datenbank ${r.service} auf Port ${r.port} exponiert`),
                ...exposedRemote.map(r => `Remote-Zugriff ${r.service} auf Port ${r.port} exponiert`)
            ];
        }

        // Check network security
        const criticalPorts = scanResults.filter(r => r.risk_level === 'critical');
        if (criticalPorts.length > 5) {
            checks.networkSecurity.status = 'fail';
            checks.networkSecurity.details.push(`${criticalPorts.length} kritische Ports offen`);
        } else if (criticalPorts.length > 0) {
            checks.networkSecurity.status = 'warning';
            checks.networkSecurity.details.push(`${criticalPorts.length} kritische Ports offen`);
        }

        return checks;
    }

    // Generate executive summary text
    static _generateSummary(scan, scoreData, findings, recommendations) {
        const critCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;
        const ratingInfo = this.RISK_THRESHOLDS[scoreData.rating];

        let summary = `Sicherheitsaudit für ${scan.target} (Scan #${scan.id})\n\n`;
        summary += `Gesamtbewertung: ${scoreData.score}/100 Punkte – ${ratingInfo.label}\n`;
        summary += `${ratingInfo.description}\n\n`;
        summary += `Es wurden insgesamt ${findings.length} Befunde identifiziert`;

        if (critCount > 0 || highCount > 0) {
            summary += `, davon ${critCount} kritische und ${highCount} hohe Schwachstellen. `;
            summary += 'Sofortige Maßnahmen sind erforderlich, um die identifizierten Risiken zu minimieren.';
        } else {
            summary += '. Keine kritischen Schwachstellen gefunden.';
        }

        summary += `\n\nEs werden ${recommendations.length} Maßnahmen empfohlen.`;

        return summary;
    }

    // Get audit by ID
    static getById(auditId) {
        const db = getDatabase();
        const audit = db.prepare('SELECT * FROM security_audits WHERE id = ?').get(auditId);
        if (!audit) return null;

        const findings = db.prepare('SELECT * FROM audit_findings WHERE audit_id = ? ORDER BY priority ASC, severity ASC').all(auditId);

        return {
            ...audit,
            recommendations: JSON.parse(audit.recommendations_json || '[]'),
            compliance: JSON.parse(audit.compliance_json || '{}'),
            findings
        };
    }

    // Get audit by scan ID
    static getByScanId(scanId) {
        const db = getDatabase();
        const audit = db.prepare('SELECT * FROM security_audits WHERE scan_id = ? ORDER BY generated_at DESC LIMIT 1').get(scanId);
        if (!audit) return null;

        const findings = db.prepare('SELECT * FROM audit_findings WHERE audit_id = ? ORDER BY priority ASC').all(audit.id);

        return {
            ...audit,
            recommendations: JSON.parse(audit.recommendations_json || '[]'),
            compliance: JSON.parse(audit.compliance_json || '{}'),
            findings
        };
    }

    // Get all audits
    static getAll(filters = {}) {
        const db = getDatabase();
        let query = `
            SELECT sa.*, s.target, s.scan_type 
            FROM security_audits sa 
            JOIN scans s ON sa.scan_id = s.id 
            WHERE 1=1
        `;
        const params = [];

        if (filters.riskRating) {
            query += ' AND sa.risk_rating = ?';
            params.push(filters.riskRating);
        }
        if (filters.scanId) {
            query += ' AND sa.scan_id = ?';
            params.push(filters.scanId);
        }

        query += ' ORDER BY sa.generated_at DESC';

        const page = filters.page || 1;
        const limit = filters.limit || 20;
        const offset = (page - 1) * limit;

        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const audits = db.prepare(query).all(...params);
        return { audits };
    }

    // Delete an audit
    static delete(auditId) {
        const db = getDatabase();
        db.prepare('DELETE FROM security_audits WHERE id = ?').run(auditId);
        logger.info(`Security audit deleted: ID ${auditId}`);
    }
}

module.exports = SecurityAuditService;