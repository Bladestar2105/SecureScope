const { initializeDatabase } = require('./config/database');
try {
    initializeDatabase();
    console.log('Database initialized.');
} catch (e) {
    console.error(e);
}
