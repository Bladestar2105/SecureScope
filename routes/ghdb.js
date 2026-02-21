const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const logger = require('../services/logger');
const GhdbService = require('../services/ghdbService');

// Search GHDB entries
router.get('/search', requireAuth, (req, res) => {
    try {
        const filters = {
            search: req.query.search,
            category: req.query.category,
            page: parseInt(req.query.page) || 1,
            limit: parseInt(req.query.limit) || 50
        };

        // Handle search query for SQL
        if (filters.search) {
            filters.search = `%${filters.search}%`;
        }

        const result = GhdbService.search(req.query); // Use raw query for service to parse
        res.json(result);
    } catch (err) {
        logger.error('Error searching GHDB:', err);
        res.status(500).json({ error: 'Fehler bei der GHDB-Suche' });
    }
});

// Get GHDB statistics
router.get('/stats', requireAuth, (req, res) => {
    try {
        const stats = GhdbService.getStats();
        res.json(stats);
    } catch (err) {
        logger.error('Error fetching GHDB stats:', err);
        res.status(500).json({ error: 'Fehler beim Laden der GHDB-Statistiken' });
    }
});

module.exports = router;
