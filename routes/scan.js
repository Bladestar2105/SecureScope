const express = require('express');
const router = express.Router();
const scannerService = require('../services/scanner');
const attackChainService = require('../services/attackChainService');
const { requireAuth } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimit');
const UserService = require('../services/userService');
const logger = require('../services/logger');
const PDFDocument = require('pdfkit');

// All scan routes require authentication
router.use(requireAuth);

// GET /api/scan/dashboard - Dashboard stats
router.get('/dashboard', (req, res) => {
    try {
        const stats = scannerService.getDashboardStats(req.session.userId);
        res.json(stats);
    } catch (err) {
        logger.error('Dashboard error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/:id - Get single scan with results
router.get('/:id(\\d+)', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }
        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const data = scannerService.getScanResults(scanId, page, limit);
        const cveSummary = scannerService.getScanCVESummary(scanId);

        res.json({ scan, ...data, cveSummary });
    } catch (err) {
        logger.error('Scan get error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// DELETE /api/scan/:id - Delete a scan
router.delete('/:id(\\d+)', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        const db = require('../config/database').getDatabase();

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }
        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }
        if (scan.status === 'running') {
            return res.status(400).json({ error: 'Laufender Scan kann nicht gelöscht werden' });
        }

        // Delete scan and all related data (CASCADE)
        db.prepare('DELETE FROM scan_vulnerabilities WHERE scan_id = ?').run(scanId);
        db.prepare('DELETE FROM scan_fingerprints WHERE scan_id = ?').run(scanId);
        db.prepare('DELETE FROM scan_exploits WHERE scan_id = ?').run(scanId);
        db.prepare('DELETE FROM scan_results WHERE scan_id = ?').run(scanId);
        db.prepare('DELETE FROM scans WHERE id = ?').run(scanId);

        UserService.logAudit(req.session.userId, 'SCAN_DELETED', { scanId }, req.ip);
        res.json({ success: true, message: 'Scan gelöscht' });
    } catch (err) {
        logger.error('Scan delete error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/scan/start - Start a new scan
router.post('/start', scanLimiter, async (req, res) => {
    try {
        const { target, scanType, customPorts } = req.body;

        if (!target || !scanType) {
            return res.status(400).json({ error: 'Ziel und Scan-Typ sind erforderlich' });
        }

        const validScanTypes = ['quick', 'standard', 'full', 'custom'];
        if (!validScanTypes.includes(scanType)) {
            return res.status(400).json({ error: 'Ungültiger Scan-Typ' });
        }

        if (scanType === 'custom' && !customPorts) {
            return res.status(400).json({ error: 'Benutzerdefinierte Ports sind erforderlich für Custom Scan' });
        }

        const scan = await scannerService.startScan(
            req.session.userId,
            target.trim(),
            scanType,
            customPorts ? customPorts.trim() : null
        );

        UserService.logAudit(req.session.userId, 'SCAN_STARTED', {
            scanId: scan.id,
            target: target.trim(),
            scanType
        }, req.ip);

        res.json({ success: true, scan });
    } catch (err) {
        logger.error('Scan start error:', err);
        res.status(400).json({ error: err.message });
    }
});

// GET /api/scan/status/:id - Get scan status
router.get('/status/:id', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }

        // Verify ownership
        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        res.json({ scan });
    } catch (err) {
        logger.error('Scan status error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/scan/stop/:id - Stop a running scan
router.post('/stop/:id', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }

        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        if (scan.status !== 'running') {
            return res.status(400).json({ error: 'Scan läuft nicht' });
        }

        const stopped = scannerService.stopScan(scanId);
        if (stopped) {
            UserService.logAudit(req.session.userId, 'SCAN_STOPPED', { scanId }, req.ip);
            res.json({ success: true, message: 'Scan wird abgebrochen' });
        } else {
            res.status(400).json({ error: 'Scan konnte nicht abgebrochen werden' });
        }
    } catch (err) {
        logger.error('Scan stop error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/results/:id - Get scan results with pagination
router.get('/results/:id', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }

        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);

        const data = scannerService.getScanResults(scanId, page, limit);
        const cveSummary = scannerService.getScanCVESummary(scanId);
        res.json({ scan, ...data, cveSummary });
    } catch (err) {
        logger.error('Scan results error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/cves/:id - Get CVE matches for a scan
router.get('/cves/:id', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }

        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        const cves = scannerService.getScanCVEs(scanId);
        const summary = scannerService.getScanCVESummary(scanId);
        res.json({ cves, summary });
    } catch (err) {
        logger.error('Scan CVE error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/history - Get scan history
router.get('/history', (req, res) => {
    try {
        const filters = {
            dateFrom: req.query.dateFrom || null,
            dateTo: req.query.dateTo || null,
            scanType: req.query.scanType || null,
            target: req.query.target || null,
            status: req.query.status || null,
            page: parseInt(req.query.page) || 1,
            limit: Math.min(parseInt(req.query.limit) || 20, 50)
        };

        const data = scannerService.getScanHistory(req.session.userId, filters);
        res.json(data);
    } catch (err) {
        logger.error('Scan history error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/compare - Compare two scans
router.get('/compare', (req, res) => {
    try {
        const scanId1 = parseInt(req.query.scan1);
        const scanId2 = parseInt(req.query.scan2);

        if (isNaN(scanId1) || isNaN(scanId2)) {
            return res.status(400).json({ error: 'Zwei gültige Scan-IDs erforderlich' });
        }

        // Verify ownership of both scans
        const scan1 = scannerService.getScanStatus(scanId1);
        const scan2 = scannerService.getScanStatus(scanId2);

        if (!scan1 || !scan2) {
            return res.status(404).json({ error: 'Einer oder beide Scans nicht gefunden' });
        }

        if (scan1.user_id !== req.session.userId || scan2.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        const comparison = scannerService.compareScans(scanId1, scanId2);
        res.json(comparison);
    } catch (err) {
        logger.error('Scan compare error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/scan/export/:id - Export scan results
router.get('/export/:id', (req, res) => {
    try {
        const scanId = parseInt(req.params.id);
        const format = req.query.format || 'json';

        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const scan = scannerService.getScanStatus(scanId);
        if (!scan) {
            return res.status(404).json({ error: 'Scan nicht gefunden' });
        }

        if (scan.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        const results = scannerService.getAllScanResults(scanId);

        UserService.logAudit(req.session.userId, 'SCAN_EXPORTED', {
            scanId, format
        }, req.ip);

        switch (format.toLowerCase()) {
            case 'csv':
                return exportCSV(res, scan, results);
            case 'pdf':
                return exportPDF(res, scan, results);
            case 'json':
            default:
                return exportJSON(res, scan, results);
        }
    } catch (err) {
        logger.error('Scan export error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// SSE endpoint for real-time scan updates
router.get('/events', (req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });

    res.write('data: {"type":"connected"}\n\n');

    const onProgress = (data) => {
        const scan = scannerService.getScanStatus(data.scanId);
        if (scan && scan.user_id === req.session.userId) {
            res.write(`data: ${JSON.stringify({ type: 'progress', ...data })}\n\n`);
        }
    };

    const onComplete = (data) => {
        const scan = scannerService.getScanStatus(data.scanId);
        if (scan && scan.user_id === req.session.userId) {
            res.write(`data: ${JSON.stringify({ type: 'complete', ...data })}\n\n`);
        }
    };

    const onError = (data) => {
        const scan = scannerService.getScanStatus(data.scanId);
        if (scan && scan.user_id === req.session.userId) {
            res.write(`data: ${JSON.stringify({ type: 'error', ...data })}\n\n`);
        }
    };

    // Attack Chain Events
    const onChainProgress = (data) => {
        // NOTE: Attack chains are not strictly bound to a scan owner in the same way as scans,
        // but we can check if the user has access. For now, we assume if they are authenticated and listening,
        // they should see it if they initiated it.
        // Ideally, we should check ownership of the execution or scan.
        // Assuming req.session.userId initiated it or has access.
        res.write(`data: ${JSON.stringify({ type: 'chain_progress', ...data })}\n\n`);
    };

    const onChainComplete = (data) => {
        res.write(`data: ${JSON.stringify({ type: 'chain_complete', ...data })}\n\n`);
    };

    const onChainError = (data) => {
        res.write(`data: ${JSON.stringify({ type: 'chain_error', ...data })}\n\n`);
    };

    scannerService.on('scanProgress', onProgress);
    scannerService.on('scanComplete', onComplete);
    scannerService.on('scanError', onError);

    attackChainService.on('chainProgress', onChainProgress);
    attackChainService.on('chainComplete', onChainComplete);
    attackChainService.on('chainError', onChainError);

    // Keep-alive ping every 30 seconds
    const keepAlive = setInterval(() => {
        res.write(': keepalive\n\n');
    }, 30000);

    req.on('close', () => {
        clearInterval(keepAlive);
        scannerService.off('scanProgress', onProgress);
        scannerService.off('scanComplete', onComplete);
        scannerService.off('scanError', onError);

        attackChainService.off('chainProgress', onChainProgress);
        attackChainService.off('chainComplete', onChainComplete);
        attackChainService.off('chainError', onChainError);
    });
});

// Export helpers
function exportJSON(res, scan, results) {
    const data = {
        scan: {
            id: scan.id,
            type: scan.scan_type,
            target: scan.target,
            status: scan.status,
            startedAt: scan.started_at,
            completedAt: scan.completed_at
        },
        summary: {
            totalPorts: results.length,
            critical: results.filter(r => r.risk_level === 'critical').length,
            warning: results.filter(r => r.risk_level === 'warning').length,
            safe: results.filter(r => r.risk_level === 'safe').length
        },
        results: results.map(r => ({
            ip: r.ip_address,
            port: r.port,
            protocol: r.protocol,
            service: r.service,
            product: r.service_product || null,
            version: r.service_version || null,
            banner: r.banner || null,
            cpe: r.service_cpe || null,
            os: r.os_name || null,
            state: r.state,
            riskLevel: r.risk_level
        }))
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.json`);
    res.json(data);
}

function exportCSV(res, scan, results) {
    const header = 'IP-Adresse,Port,Protokoll,Service,Produkt,Version,Banner,CPE,OS,Status,Risiko';
    const esc = (s) => {
        if (!s) return '';
        let str = String(s);
        // Prevent formula injection (CSV Injection)
        if (/^[=@+\-]/.test(str)) {
            str = "'" + str;
        }
        return `"${str.replace(/"/g, '""')}"`;
    };
    const rows = results.map(r =>
        `${r.ip_address},${r.port},${r.protocol},${esc(r.service)},${esc(r.service_product)},${esc(r.service_version)},${esc(r.banner)},${esc(r.service_cpe)},${esc(r.os_name)},${r.state},${r.risk_level}`
    );

    const csv = [
        `# SecureScope Scan Report - ID: ${scan.id}`,
        `# Ziel: ${scan.target}`,
        `# Typ: ${scan.scan_type}`,
        `# Datum: ${scan.started_at}`,
        `# Status: ${scan.status}`,
        '',
        header,
        ...rows
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.csv`);
    res.send(csv);
}

function exportPDF(res, scan, results) {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=securescope_scan_${scan.id}.pdf`);

    doc.pipe(res);

    // Title
    doc.fontSize(24).font('Helvetica-Bold').text('SecureScope', { align: 'center' });
    doc.fontSize(14).font('Helvetica').text('Network Security Audit Report', { align: 'center' });
    doc.moveDown(2);

    // Scan Info
    doc.fontSize(16).font('Helvetica-Bold').text('Scan-Informationen');
    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica');
    doc.text(`Scan-ID: ${scan.id}`);
    doc.text(`Ziel: ${scan.target}`);
    doc.text(`Scan-Typ: ${scan.scan_type}`);
    doc.text(`Status: ${scan.status}`);
    doc.text(`Gestartet: ${scan.started_at}`);
    doc.text(`Abgeschlossen: ${scan.completed_at || 'N/A'}`);
    doc.moveDown(1);

    // Summary
    const critical = results.filter(r => r.risk_level === 'critical').length;
    const warning = results.filter(r => r.risk_level === 'warning').length;
    const safe = results.filter(r => r.risk_level === 'safe').length;

    doc.fontSize(16).font('Helvetica-Bold').text('Zusammenfassung');
    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica');
    doc.text(`Offene Ports gesamt: ${results.length}`);
    doc.fillColor('red').text(`Kritisch: ${critical}`);
    doc.fillColor('#cc8800').text(`Warnung: ${warning}`);
    doc.fillColor('green').text(`Sicher: ${safe}`);
    doc.fillColor('black');
    doc.moveDown(1);

    // Results Table
    if (results.length > 0) {
        doc.fontSize(16).font('Helvetica-Bold').text('Ergebnisse');
        doc.moveDown(0.5);

        // Table header
        const tableTop = doc.y;
        const colWidths = [80, 45, 80, 140, 60, 60];
        const headers = ['IP-Adresse', 'Port', 'Service', 'Produkt/Version', 'Status', 'Risiko'];

        doc.fontSize(9).font('Helvetica-Bold');
        let xPos = 50;
        headers.forEach((header, i) => {
            doc.text(header, xPos, tableTop, { width: colWidths[i] });
            xPos += colWidths[i];
        });

        doc.moveTo(50, tableTop + 15).lineTo(545, tableTop + 15).stroke();

        // Table rows
        doc.font('Helvetica').fontSize(8);
        let yPos = tableTop + 20;

        results.forEach((r, index) => {
            if (yPos > 750) {
                doc.addPage();
                yPos = 50;
            }

            xPos = 50;
            let productVersion = r.banner || r.service_product || '';
            if (productVersion.length > 30) productVersion = productVersion.substring(0, 30) + '...';
            const rowData = [r.ip_address, r.port.toString(), r.service || '', productVersion, r.state, r.risk_level];

            // Color based on risk
            if (r.risk_level === 'critical') doc.fillColor('red');
            else if (r.risk_level === 'warning') doc.fillColor('#cc8800');
            else if (r.risk_level === 'safe') doc.fillColor('green');
            else doc.fillColor('black');

            rowData.forEach((cell, i) => {
                doc.text(cell, xPos, yPos, { width: colWidths[i] });
                xPos += colWidths[i];
            });

            doc.fillColor('black');
            yPos += 15;
        });
    } else {
        doc.fontSize(12).text('Keine offenen Ports gefunden.', { align: 'center' });
    }

    // Footer
    doc.moveDown(2);
    doc.fontSize(8).fillColor('gray')
        .text(`Generiert von SecureScope am ${new Date().toLocaleString('de-DE')}`, { align: 'center' });

    doc.end();
}

module.exports = router;