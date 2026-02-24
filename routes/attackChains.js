const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission, getUserPermissions } = require('../middleware/rbac');
const attackChainService = require('../services/attackChainService');
const logger = require('../services/logger');

// Get all attack chains
router.get('/', requireAuth, (req, res) => {
    try {
        const filters = {
            strategy: req.query.strategy,
            riskLevel: req.query.riskLevel,
            enabled: req.query.enabled !== undefined ? req.query.enabled === 'true' : undefined,
            search: req.query.search
        };
        const chains = attackChainService.getAll(filters);
        res.json({ chains });
    } catch (err) {
        logger.error('Error fetching attack chains:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Angriffsketten' });
    }
});

// Get available strategies
router.get('/strategies', requireAuth, (req, res) => {
    try {
        const strategies = attackChainService.getStrategies();
        res.json(strategies);
    } catch (err) {
        logger.error('Error fetching strategies:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Strategien' });
    }
});

// Get ALL execution history (not scan-specific)
router.get('/executions/history', requireAuth, (req, res) => {
    try {
        const { getDatabase } = require('../config/database');
        const db = getDatabase();

        // RBAC Check
        const { roles } = getUserPermissions(req.session.userId);
        const isAdmin = roles.includes('admin');
        const userId = req.session.userId;

        let query = `
            SELECT e.*, c.name as chain_name 
            FROM attack_chain_executions e
            LEFT JOIN attack_chains c ON e.chain_id = c.id
        `;
        const params = [];

        if (!isAdmin) {
            query += ' WHERE e.executed_by = ?';
            params.push(userId);
        }

        query += ' ORDER BY e.started_at DESC LIMIT 50';

        const executions = db.prepare(query).all(...params);
        res.json({ executions });
    } catch (err) {
        logger.error('Error fetching execution history:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Ausführungshistorie' });
    }
});

// Get applicable chains for a scan
router.get('/applicable/:scanId', requireAuth, (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);
        const applicable = attackChainService.findApplicableChains(scanId);
        res.json(applicable);
    } catch (err) {
        logger.error('Error finding applicable chains:', err);
        res.status(500).json({ error: 'Fehler beim Suchen anwendbarer Ketten' });
    }
});

// Get executions for a scan
router.get('/executions/scan/:scanId', requireAuth, (req, res) => {
    try {
        const scanId = parseInt(req.params.scanId);

        // RBAC Check
        const { roles } = getUserPermissions(req.session.userId);
        const isAdmin = roles.includes('admin');
        const userId = isAdmin ? null : req.session.userId;

        const executions = attackChainService.getExecutions(scanId, userId);
        res.json({ executions });
    } catch (err) {
        logger.error('Error fetching executions:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Ausführungen' });
    }
});

// Get execution by ID
router.get('/executions/:id', requireAuth, (req, res) => {
    try {
        const exec = attackChainService.getExecutionById(parseInt(req.params.id));
        if (!exec) return res.status(404).json({ error: 'Ausführung nicht gefunden' });

        // RBAC Check
        const { roles } = getUserPermissions(req.session.userId);
        const isAdmin = roles.includes('admin');

        if (!isAdmin && exec.executed_by !== req.session.userId) {
            return res.status(403).json({ error: 'Zugriff verweigert' });
        }

        res.json({ execution: exec });
    } catch (err) {
        logger.error('Error fetching execution:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Ausführung' });
    }
});

// Get chain by ID
router.get('/:id', requireAuth, (req, res) => {
    try {
        const chain = attackChainService.getById(parseInt(req.params.id));
        if (!chain) return res.status(404).json({ error: 'Angriffskette nicht gefunden' });
        res.json(chain);
    } catch (err) {
        logger.error('Error fetching attack chain:', err);
        res.status(500).json({ error: 'Fehler beim Laden der Angriffskette' });
    }
});

// ============================================
// NEW: Auto-Attack endpoint (1-click for auditors)
// ============================================
router.post('/auto-attack', requireAuth, requirePermission('scan:start'), async (req, res) => {
    try {
        const { scanId, targetIp, params } = req.body;
        if (!scanId || !targetIp) {
            return res.status(400).json({ error: 'scanId und targetIp sind erforderlich' });
        }

        const result = await attackChainService.autoAttack(
            parseInt(scanId),
            targetIp,
            req.session.userId,
            params || {}
        );

        if (result.status === 'no_exploits' || result.status === 'no_executable_exploits') {
            return res.json(result);
        }

        res.json(result);
    } catch (err) {
        logger.error('Error in auto-attack:', err);
        res.status(500).json({ error: err.message || 'Fehler beim automatischen Angriff' });
    }
});

// Execute an attack chain (legacy endpoint)
router.post('/execute', requireAuth, requirePermission('scan:start'), async (req, res) => {
    try {
        const { scanId, chainId, targetIp, targetPort, params } = req.body;
        if (!scanId || !chainId) {
            return res.status(400).json({ error: 'scanId und chainId sind erforderlich' });
        }
        let ip = targetIp;
        if (!ip) {
            const { getDatabase } = require('../config/database');
            const db = getDatabase();
            const scan = db.prepare('SELECT target FROM scans WHERE id = ?').get(parseInt(scanId));
            ip = scan ? scan.target : '0.0.0.0';
        }
        const result = await attackChainService.executeChain(
            parseInt(scanId), parseInt(chainId), ip,
            targetPort ? parseInt(targetPort) : null,
            req.session.userId,
            params || {}
        );
        res.json(result);
    } catch (err) {
        logger.error('Error executing attack chain:', err);
        res.status(500).json({ error: err.message || 'Fehler bei der Ausführung der Angriffskette' });
    }
});

// Execute a specific chain by ID
router.post('/:id/execute', requireAuth, requirePermission('scan:start'), async (req, res) => {
    try {
        const chainId = parseInt(req.params.id);
        const { scanId, targetIp, targetPort, params } = req.body;
        if (!scanId) {
            return res.status(400).json({ error: 'scanId ist erforderlich' });
        }
        let ip = targetIp;
        if (!ip) {
            const { getDatabase } = require('../config/database');
            const db = getDatabase();
            const scan = db.prepare('SELECT target FROM scans WHERE id = ?').get(parseInt(scanId));
            ip = scan ? scan.target : '0.0.0.0';
        }
        const result = await attackChainService.executeChain(
            parseInt(scanId), chainId, ip,
            targetPort ? parseInt(targetPort) : null,
            req.session.userId,
            params || {}
        );
        res.json(result);
    } catch (err) {
        logger.error('Error executing attack chain:', err);
        res.status(500).json({ error: err.message || 'Fehler bei der Ausführung der Angriffskette' });
    }
});

// Create a custom attack chain
router.post('/', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const id = attackChainService.create(req.body, req.session.userId);
        res.status(201).json({ id, message: 'Angriffskette erstellt' });
    } catch (err) {
        logger.error('Error creating attack chain:', err);
        res.status(500).json({ error: 'Fehler beim Erstellen der Angriffskette' });
    }
});

// Toggle chain enabled/disabled
router.patch('/:id/toggle', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        const enabled = attackChainService.toggleEnabled(parseInt(req.params.id));
        res.json({ enabled, message: enabled ? 'Angriffskette aktiviert' : 'Angriffskette deaktiviert' });
    } catch (err) {
        logger.error('Error toggling attack chain:', err);
        res.status(500).json({ error: err.message || 'Fehler beim Umschalten' });
    }
});

// Delete a chain
router.delete('/:id', requireAuth, requirePermission('vulnerabilities:edit'), (req, res) => {
    try {
        attackChainService.delete(parseInt(req.params.id));
        res.json({ message: 'Angriffskette gelöscht' });
    } catch (err) {
        logger.error('Error deleting attack chain:', err);
        res.status(500).json({ error: 'Fehler beim Löschen der Angriffskette' });
    }
});

module.exports = router;