const { getDatabase } = require('../config/database');
const logger = require('./logger');

class GhdbService {

    /**
     * Ensure the GHDB table exists.
     * This is a fallback in case schema initialization failed.
     */
    static ensureTable() {
        const db = getDatabase();
        try {
            const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ghdb_entries'").get();
            if (!tableExists) {
                logger.warn('GHDB table missing, attempting to create...');
                db.exec(`
                    CREATE TABLE IF NOT EXISTS ghdb_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ghdb_id TEXT UNIQUE,
                        query TEXT,
                        category TEXT,
                        short_description TEXT,
                        textual_description TEXT,
                        date TEXT,
                        author TEXT,
                        source TEXT DEFAULT 'ghdb',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_ghdb_category ON ghdb_entries(category);
                    CREATE INDEX IF NOT EXISTS idx_ghdb_query ON ghdb_entries(query);
                `);
                logger.info('GHDB table created successfully.');
            }
        } catch (e) {
            logger.error('Error ensuring GHDB table:', e);
        }
    }

    /**
     * Search GHDB entries with pagination and filters
     */
    static search(filters = {}) {
        const db = getDatabase();

        // Lazy check for table existence
        try {
            db.prepare('SELECT 1 FROM ghdb_entries LIMIT 1').get();
        } catch (e) {
            if (e.message.includes('no such table')) {
                GhdbService.ensureTable();
            } else {
                throw e;
            }
        }

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
            // Lazy check
            try {
                db.prepare('SELECT 1 FROM ghdb_entries LIMIT 1').get();
            } catch (e) {
                if (e.message.includes('no such table')) {
                    GhdbService.ensureTable();
                } else {
                    throw e;
                }
            }

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
