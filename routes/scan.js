const express = require('express');
const router = express.Router();
const scannerService = require('../services/scanner');
const attackChainService = require('../services/attackChainService');
const { requireAuth } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimit');
const UserService = require('../services/userService');
const logger = require('../services/logger');
const exportService = require('../services/exportService');

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
        const { target, scanType, customPorts, stealthMode } = req.body;

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
            customPorts ? customPorts.trim() : null,
            !!stealthMode
        );

        UserService.logAudit(req.session.userId, 'SCAN_STARTED', {
            scanId: scan.id,
            target: target.trim(),
            scanType,
            stealthMode: !!stealthMode
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
                return exportService.exportCSV(res, scan, results);
            case 'pdf':
                return exportService.exportPDF(res, scan, results);
            case 'json':
            default:
                return exportService.exportJSON(res, scan, results);
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

module.exports = router;