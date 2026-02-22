const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/rbac');
const logStreamService = require('../services/logStreamService');

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

module.exports = router;