const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const FingerprintService = require('../services/fingerprintService');
const logger = require('../services/logger');

// Get all fingerprints
router.get('/', requireAuth, (req, res) => {
    try {
        const filters = {
            port: req.query.port ? parseInt(req.query.port) : undefined,
            service: req.query.service,
            os: req.query.os,
            search: req.query.search,
            page: parseInt(req.query.page) || 1,
            limit: parseInt(req.query.limit) || 50
        };
        const result = FingerprintService.getAll(filters);
        res.json(result);
    } catch (err) {
        logger.error('Error fetching fingerprints:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Fingerprints' });
    }
});

// Get fingerprints for a specific scan
router.get('/scan/:scanId', requireAuth, (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);
        const fingerprints = FingerprintService.getScanFingerprints(scanId);
        const osSummary = FingerprintService.getScanOSSummary(scanId);
        const serviceSummary = FingerprintService.getScanServiceSummary(scanId);
        res.json({ fingerprints, osSummary, serviceSummary });
    } catch (err) {
        logger.error('Error fetching scan fingerprints:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Scan-Fingerprints' });
    }
});

// Run fingerprint matching for a scan
router.post('/match/:scanId', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);
        const matches = FingerprintService.matchScanResults(scanId);
        res.json({ matches, count: matches.length });
    } catch (err) {
        logger.error('Error matching fingerprints:', err);
        res.status(500).json({ error: 'Fehler beim Fingerprint-Matching' });
    }
});

// Create a new fingerprint
router.post('/', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const id = FingerprintService.create(req.body);
        res.status(201).json({ id, message: 'Fingerprint erstellt' });
    } catch (err) {
        logger.error('Error creating fingerprint:', err);
        res.status(500).json({ error: 'Fehler beim Erstellen des Fingerprints' });
    }
});

// Delete a fingerprint
router.delete('/:id', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        FingerprintService.delete(parseInt(req.params.id));
        res.json({ message: 'Fingerprint gelöscht' });
    } catch (err) {
        logger.error('Error deleting fingerprint:', err);
        res.status(500).json({ error: 'Fehler beim Löschen des Fingerprints' });
    }
});

module.exports = router;