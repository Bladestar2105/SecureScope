const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const SecurityAuditService = require('../services/securityAuditService');
const logger = require('../services/logger');

// Get all audits
router.get('/', requireAuth, (req, res) => {
    try {
        const filters = {
            riskRating: req.query.riskRating,
            scanId: req.query.scanId ? parseInt(req.query.scanId) : undefined,
            page: parseInt(req.query.page) || 1,
            limit: parseInt(req.query.limit) || 20
        };
        const result = SecurityAuditService.getAll(filters);
        res.json(result);
    } catch (err) {
        logger.error('Error fetching audits:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Audits' });
    }
});

// Generate a new audit (body: { scanId, auditType })
router.post('/generate', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        const scanId = parseInt(req.body.scanId);
        const auditType = req.body.auditType || 'full';
        if (!scanId) return res.status(400).json({ error: 'scanId ist erforderlich' });
        const audit = SecurityAuditService.generateAudit(scanId, req.session.userId, auditType);
        res.status(201).json(audit);
    } catch (err) {
        logger.error('Error generating audit:', err);
        res.status(500).json({ error: err.message || 'Fehler beim Generieren des Audits' });
    }
});

// Generate a new audit (URL param variant)
router.post('/generate/:scanId', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);
        const auditType = req.body.auditType || 'full';
        const audit = SecurityAuditService.generateAudit(scanId, req.session.userId, auditType);
        res.status(201).json(audit);
    } catch (err) {
        logger.error('Error generating audit:', err);
        res.status(500).json({ error: err.message || 'Fehler beim Generieren des Audits' });
    }
});

// Get risk thresholds
router.get('/config/thresholds', requireAuth, (req, res) => {
    res.json(SecurityAuditService.RISK_THRESHOLDS);
});

// Get audit by ID (with findings)
router.get('/:id', requireAuth, (req, res) => {
    try {
        const audit = SecurityAuditService.getById(parseInt(req.params.id));
        if (!audit) return res.status(404).json({ error: 'Audit nicht gefunden' });
        res.json({ audit });
    } catch (err) {
        logger.error('Error fetching audit:', err);
        res.status(500).json({ error: 'Fehler beim Laden des Audits' });
    }
});

// Get audit by scan ID
router.get('/scan/:scanId', requireAuth, (req, res) => {
    try {
        const audit = SecurityAuditService.getByScanId(parseInt(req.params.scanId));
        if (!audit) return res.status(404).json({ error: 'Kein Audit für diesen Scan gefunden' });
        res.json({ audit });
    } catch (err) {
        logger.error('Error fetching audit by scan:', err);
        res.status(500).json({ error: 'Fehler beim Laden des Audits' });
    }
});

// Delete an audit
router.delete('/:id', requireAuth, requirePermission('scan:delete'), (req, res) => {
    try {
        SecurityAuditService.delete(parseInt(req.params.id));
        res.json({ message: 'Audit gelöscht' });
    } catch (err) {
        logger.error('Error deleting audit:', err);
        res.status(500).json({ error: 'Fehler beim Löschen des Audits' });
    }
});

module.exports = router;