const { getDatabase } = require('../config/database');
const logger = require('./logger');

class GhdbService {

    /**
     * Search GHDB entries with pagination and filters
     */
    static search(filters = {}) {
        const db = getDatabase();
        const page = parseInt(filters.page) || 1;
        const limit = parseInt(filters.limit) || 50;
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM ghdb_entries WHERE 1=1';
        const params = [];

        if (filters.search) {
            query += ' AND (query LIKE ? OR short_description LIKE ? OR textual_description LIKE ?)';
            const term = `%${filters.search}%`;
            params.push(term, term, term);
        }

        if (filters.category) {
            query += ' AND category LIKE ?';
            params.push(`%${filters.category}%`);
        }

        // Count total
        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as c');
        const total = db.prepare(countQuery).get(...params).c;

        // Fetch data
        query += ' ORDER BY date DESC, id DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const entries = db.prepare(query).all(...params);

        return {
            entries,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        };
    }

    /**
     * Get GHDB statistics
     */
    static getStats() {
        const db = getDatabase();
        try {
            const total = db.prepare('SELECT COUNT(*) as c FROM ghdb_entries').get().c;
            const byCategory = db.prepare('SELECT category, COUNT(*) as count FROM ghdb_entries GROUP BY category ORDER BY count DESC').all();
            const lastSync = db.prepare("SELECT completed_at FROM db_update_log WHERE database_type = 'ghdb' AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").get()?.completed_at;

            return { total, byCategory, lastSync };
        } catch (e) {
            logger.error('Error fetching GHDB stats:', e);
            return { total: 0, byCategory: [], lastSync: null };
        }
    }
}

module.exports = GhdbService;
