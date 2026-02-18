const express = require('express');
const router = express.Router();
const schedulerService = require('../services/schedulerService');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const logger = require('../services/logger');

router.use(requireAuth);

// GET /api/schedules - List all scheduled scans for current user
router.get('/', requirePermission('schedule:view'), (req, res) => {
    try {
        const schedules = schedulerService.getAll(req.session.userId);
        res.json({ schedules });
    } catch (err) {
        logger.error('Schedule list error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// GET /api/schedules/presets - Get cron presets
router.get('/presets', (req, res) => {
    res.json({ presets: schedulerService.constructor.getCronPresets() });
});

// GET /api/schedules/:id - Get single schedule
router.get('/:id', requirePermission('schedule:view'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Ungültige ID' });

        const schedule = schedulerService.getById(id, req.session.userId);
        if (!schedule) return res.status(404).json({ error: 'Geplanter Scan nicht gefunden' });

        res.json({ schedule });
    } catch (err) {
        logger.error('Schedule get error:', err);
        res.status(500).json({ error: 'Interner Serverfehler' });
    }
});

// POST /api/schedules - Create new scheduled scan
router.post('/', requirePermission('schedule:create'), (req, res) => {
    try {
        const { name, target, scanType, customPorts, cronExpression, notifyOnComplete, notifyOnCritical, enabled } = req.body;

        if (!name || !target || !scanType || !cronExpression) {
            return res.status(400).json({ error: 'Name, Ziel, Scan-Typ und Cron-Ausdruck sind erforderlich' });
        }

        const schedule = schedulerService.create(req.session.userId, {
            name, target, scanType, customPorts, cronExpression,
            notifyOnComplete, notifyOnCritical, enabled
        });

        res.json({ success: true, schedule });
    } catch (err) {
        logger.error('Schedule create error:', err);
        res.status(400).json({ error: err.message });
    }
});

// PUT /api/schedules/:id - Update scheduled scan
router.put('/:id', requirePermission('schedule:edit'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Ungültige ID' });

        const schedule = schedulerService.update(id, req.session.userId, req.body);
        res.json({ success: true, schedule });
    } catch (err) {
        logger.error('Schedule update error:', err);
        res.status(400).json({ error: err.message });
    }
});

// POST /api/schedules/:id/toggle - Toggle schedule enabled/disabled
router.post('/:id/toggle', requirePermission('schedule:edit'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Ungültige ID' });

        const enabled = schedulerService.toggle(id, req.session.userId);
        res.json({ success: true, enabled, message: enabled ? 'Geplanter Scan aktiviert' : 'Geplanter Scan deaktiviert' });
    } catch (err) {
        logger.error('Schedule toggle error:', err);
        res.status(400).json({ error: err.message });
    }
});

// DELETE /api/schedules/:id - Delete scheduled scan
router.delete('/:id', requirePermission('schedule:delete'), (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Ungültige ID' });

        schedulerService.delete(id, req.session.userId);
        res.json({ success: true, message: 'Geplanter Scan gelöscht' });
    } catch (err) {
        logger.error('Schedule delete error:', err);
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;