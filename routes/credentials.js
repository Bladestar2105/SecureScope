const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const CredentialService = require('../services/credentialService');
const logger = require('../services/logger');

// Get all credentials (masked)
router.get('/', requireAuth, (req, res) => {
    try {
        const filters = {
            type: req.query.type,
            authMethod: req.query.authMethod,
            search: req.query.search,
            valid: req.query.valid !== undefined ? req.query.valid === 'true' : undefined
        };
        const credentials = CredentialService.getAll(req.session.userId, filters);
        res.json(credentials);
    } catch (err) {
        logger.error('Error fetching credentials:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Zugangsdaten' });
    }
});

// Get auth methods
router.get('/auth-methods', requireAuth, (req, res) => {
    res.json(CredentialService.AUTH_METHODS);
});

// Get credential statistics
router.get('/stats', requireAuth, (req, res) => {
    try {
        const stats = CredentialService.getStats(req.session.userId);
        res.json(stats);
    } catch (err) {
        logger.error('Error fetching credential stats:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Statistiken' });
    }
});

// Get credentials for a target
router.get('/for-target', requireAuth, (req, res) => {
    try {
        const { ip, port, service } = req.query;
        const credentials = CredentialService.getForTarget(
            req.session.userId, ip, port ? parseInt(port) : null, service
        );
        res.json(credentials);
    } catch (err) {
        logger.error('Error fetching target credentials:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Zugangsdaten' });
    }
});

// Get credential by ID (without secrets)
router.get('/:id', requireAuth, (req, res) => {
    try {
        const cred = CredentialService.getById(parseInt(req.params.id), req.session.userId, false);
        if (!cred) return res.status(404).json({ error: 'Zugangsdaten nicht gefunden' });
        res.json(cred);
    } catch (err) {
        logger.error('Error fetching credential:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Zugangsdaten' });
    }
});

// Get usage log for a credential
router.get('/:id/usage', requireAuth, (req, res) => {
    try {
        const log = CredentialService.getUsageLog(parseInt(req.params.id), req.session.userId);
        res.json(log);
    } catch (err) {
        logger.error('Error fetching usage log:', err);
        res.status(500).json({ error: 'Fehler beim Laden des Nutzungsprotokolls' });
    }
});

// Create a new credential
router.post('/', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        const id = CredentialService.create(req.session.userId, req.body);
        res.status(201).json({ id, message: 'Zugangsdaten erstellt' });
    } catch (err) {
        logger.error('Error creating credential:', err);
        res.status(400).json({ error: err.message || 'Fehler beim Erstellen der Zugangsdaten' });
    }
});

// Update a credential
router.put('/:id', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        CredentialService.update(parseInt(req.params.id), req.session.userId, req.body);
        res.json({ message: 'Zugangsdaten aktualisiert' });
    } catch (err) {
        logger.error('Error updating credential:', err);
        res.status(400).json({ error: err.message || 'Fehler beim Aktualisieren der Zugangsdaten' });
    }
});

// Delete a credential
router.delete('/:id', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        CredentialService.delete(parseInt(req.params.id), req.session.userId);
        res.json({ message: 'Zugangsdaten gelöscht' });
    } catch (err) {
        logger.error('Error deleting credential:', err);
        res.status(400).json({ error: err.message || 'Fehler beim Löschen der Zugangsdaten' });
    }
});

module.exports = router;