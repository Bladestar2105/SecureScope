const Database = require('better-sqlite3');
const path = require('path');

// Determine DB path similar to app
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'database', 'securescope.db');
console.log(`Connecting to database at ${DB_PATH}`);

try {
    const db = new Database(DB_PATH);

    // Find exploits related to MS06-040 or CVE-2006-3439
    // Also include 'NetAPI' exploits that might be relevant if user searches for them
    const exploits = db.prepare(`
        SELECT id, title, service_name, port, source, cve_id
        FROM exploits
        WHERE title LIKE '%MS06-040%'
           OR cve_id = 'CVE-2006-3439'
           OR (title LIKE '%NetAPI%' AND title LIKE '%Buffer Overflow%' AND platform LIKE '%Windows%')
    `).all();

    console.log(`Found ${exploits.length} potential exploits to update.`);

    const updateStmt = db.prepare(`
        UPDATE exploits
        SET service_name = 'smb', port = 445
        WHERE id = ?
    `);

    let count = 0;
    const updateTransaction = db.transaction((matches) => {
        for (const ex of matches) {
            // Only update if not already correct (to avoid unnecessary writes, though not critical)
            if (ex.service_name !== 'smb' || ex.port !== 445) {
                console.log(`[UPDATE] ID: ${ex.id} | Title: ${ex.title} | Old: ${ex.service_name}:${ex.port} -> New: smb:445`);
                updateStmt.run(ex.id);
                count++;
            } else {
                console.log(`[SKIP] ID: ${ex.id} | Title: ${ex.title} | Already correct.`);
            }
        }
    });

    updateTransaction(exploits);
    console.log(`Successfully updated ${count} exploits.`);

} catch (err) {
    console.error('Error running fix script:', err);
    process.exit(1);
}
