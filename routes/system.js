const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const logStreamService = require('../services/logStreamService');
const metasploitConsoleService = require('../services/metasploitConsoleService');

// ============================================
// Live Log Stream (SSE)
// ============================================
router.get('/logs/stream', requireAuth, (req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });

    // Send initial ping
    res.write("event: ping\ndata: connected\n\n");

    // Register client
    logStreamService.addClient(res);

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
        res.write("event: ping\ndata: \n\n");
    }, 15000);

    req.on('close', () => {
        clearInterval(heartbeat);
        logStreamService.removeClient(res);
    });
});

// ============================================
// Metasploit Browser Console
// ============================================
router.post('/metasploit/session', requireAuth, requirePermission('scan:start'), (req, res) => {
    try {
        const { bootstrapCommands } = req.body || {};
        const { sessionId, command } = metasploitConsoleService.startSession(req.session.userId, {
            bootstrapCommands
        });
        res.status(201).json({
            sessionId,
            command,
            message: 'Metasploit-Konsole gestartet'
        });
    } catch (err) {
        res.status(500).json({ error: err.message || 'Metasploit-Konsole konnte nicht gestartet werden' });
    }
});

router.delete('/metasploit/session/:id', requireAuth, requirePermission('scan:start'), (req, res) => {
    const sessionId = req.params.id;
    const session = metasploitConsoleService.getSession(sessionId);

    if (!session) {
        return res.status(404).json({ error: 'Session nicht gefunden' });
    }

    if (session.createdBy !== req.session.userId && !(req.userRoles || []).includes('admin')) {
        return res.status(403).json({ error: 'Zugriff verweigert' });
    }

    metasploitConsoleService.stopSession(sessionId);
    res.json({ message: 'Metasploit-Session beendet' });
});

module.exports = router;
