const express = require('express');
const router = express.Router();
const VulnerabilityService = require('../services/vulnerabilityService');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const logger = require('../services/logger');

// All vulnerability routes require authentication
router.use(requireAuth);

// GET /api/vulnerabilities - List all vulnerabilities with filters
router.get('/', (req, res) => {
    try {
        const filters = {
            severity: req.query.severity || null,
            service: req.query.service || null,
            port: req.query.port ? parseInt(req.query.port) : null,
            search: req.query.search || null,
            page: parseInt(req.query.page) || 1,
            limit: Math.min(parseInt(req.query.limit) || 50, 100)
        };

        const data = VulnerabilityService.getAll(filters);
        res.json(data);
    } catch (err) {
        logger.error('Vulnerability list error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/vulnerabilities/scan/:scanId - Get vulnerabilities for a scan
router.get('/scan/:scanId', (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);
        if (isNaN(scanId)) {
            return res.status(400).json({ error: 'Ungültige Scan-ID' });
        }

        const vulnerabilities = VulnerabilityService.getScanVulnerabilities(scanId);
        const summary = VulnerabilityService.getScanVulnerabilitySummary(scanId);

        res.json({ vulnerabilities, summary });
    } catch (err) {
        logger.error('Scan vulnerability error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/vulnerabilities/:id - Get single vulnerability
router.get('/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({ error: 'Ungültige ID' });
        }

        const vuln = VulnerabilityService.getById(id);
        if (!vuln) {
            return res.status(404).json({ error: 'Schwachstelle nicht gefunden' });
        }

        res.json({ vulnerability: vuln });
    } catch (err) {
        logger.error('Vulnerability get error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/vulnerabilities - Create new vulnerability (admin only)
router.post('/', requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const { cveId, port, protocol, service, severity, title, description, remediation, cvssScore, referencesUrl } = req.body;

        if (!port || !service || !severity || !title) {
            return res.status(400).json({ error: 'Port, Service, Severity und Titel sind erforderlich' });
        }

        const validSeverities = ['critical', 'high', 'medium', 'low'];
        if (!validSeverities.includes(severity)) {
            return res.status(400).json({ error: 'Ungültige Severity (critical, high, medium, low)' });
        }

        const id = VulnerabilityService.create({
            cveId, port: parseInt(port), protocol, service, severity,
            title, description, remediation, cvssScore: cvssScore ? parseFloat(cvssScore) : null,
            referencesUrl
        });

        res.json({ success: true, id });
    } catch (err) {
        logger.error('Vulnerability create error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// PUT /api/vulnerabilities/:id - Update vulnerability (admin only)
router.put('/:id', requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({ error: 'Ungültige ID' });
        }

        const existing = VulnerabilityService.getById(id);
        if (!existing) {
            return res.status(404).json({ error: 'Schwachstelle nicht gefunden' });
        }

        VulnerabilityService.update(id, req.body);
        res.json({ success: true, message: 'Schwachstelle aktualisiert' });
    } catch (err) {
        logger.error('Vulnerability update error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// DELETE /api/vulnerabilities/:id - Delete vulnerability (admin only)
router.delete('/:id', requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            return res.status(400).json({ error: 'Ungültige ID' });
        }

        VulnerabilityService.delete(id);
        res.json({ success: true, message: 'Schwachstelle gelöscht' });
    } catch (err) {
        logger.error('Vulnerability delete error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

module.exports = router;