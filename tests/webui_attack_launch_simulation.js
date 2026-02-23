const { chromium } = require('playwright');
const assert = require('assert');

(async () => {
    console.log('Starting WebUI Auto Attack Simulation...');
    const browser = await chromium.launch({ args: ['--no-sandbox'] });
    const context = await browser.newContext();
    const page = await context.newPage();

    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', exception => console.log(`PAGE ERROR: "${exception}"`));

    try {
        // Mock APIs
        await page.route('**/api/auth/status', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ authenticated: true, user: { username: 'admin' }, csrfToken: 'abc' })
            });
        });

        await page.route('**/api/users/me/permissions', async route => {
             await route.fulfill({ status: 200, body: JSON.stringify({ roles: ['admin'], permissions: [] }) });
        });

        await page.route('**/api/scan/dashboard', async route => {
            await route.fulfill({ status: 200, body: JSON.stringify({ activeScans: 0, recentScans: [] }) });
        });

        await page.route('**/api/scan/history', async route => {
            await route.fulfill({ status: 200, body: JSON.stringify({ scans: [] }) });
        });

        await page.route('**/api/scan/events', async route => {
             await route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
        });

        // Mock matched exploits
        await page.route('**/api/exploits/matched/101/192.168.178.231', async route => {
            await route.fulfill({
                status: 200, body: JSON.stringify({
                    exploits: [{
                        exploit_id: 130555,
                        exploit_title: 'MS08-067 NetAPI',
                        match_confidence: 100,
                        port: 445,
                        ip_address: '192.168.178.231',
                        exploit_db_id: 'exploits/windows/smb/ms08_067_netapi'
                    }]
                })
            });
        });

        // Mock attackable summary
        await page.route('**/api/exploits/attackable/101/192.168.178.231', async route => {
             await route.fulfill({
                 status: 200,
                 body: JSON.stringify({
                     services: [{
                         port: 445,
                         service: 'microsoft-ds',
                         version: 'Windows XP',
                         hasExploits: true,
                         exploitCount: 1,
                         maxConfidence: 100,
                         severities: 'critical'
                     }]
                 })
             });
        });

        // Mock Auto Attack Launch
        let attackStarted = false;
        await page.route('**/api/attack-chains/auto-attack', async route => {
            if (route.request().method() === 'POST') {
                const payload = route.request().postDataJSON();
                console.log('Intercepted POST to /api/attack-chains/auto-attack:', JSON.stringify(payload, null, 2));

                if (payload.scanId === 101 && payload.targetIp === '192.168.178.231') {
                     attackStarted = true;
                     await route.fulfill({
                         status: 200,
                         body: JSON.stringify({
                             executionId: 100,
                             status: 'running',
                             totalSteps: 5,
                             totalExploits: 1,
                             attackableServices: 1
                         })
                     });
                } else {
                     await route.fulfill({ status: 400, body: JSON.stringify({ error: 'Invalid payload' }) });
                }
            } else {
                await route.continue();
            }
        });

        // Load Dashboard
        console.log('Loading dashboard...');
        await page.goto('http://localhost:3000/dashboard.html');
        await page.waitForTimeout(2000);

        // Trigger "Auto Attack" via window function exposed by dashboard.js
        console.log('Triggering showAutoAttackModal(101, "192.168.178.231")...');

        // Wait for function to be available
        await page.waitForFunction(() => typeof window.showAutoAttackModal === 'function');

        // Open modal
        await page.evaluate(() => window.showAutoAttackModal(101, '192.168.178.231'));
        await page.waitForTimeout(1000); // Wait for modal animation

        // Check if modal is visible
        const modalVisible = await page.isVisible('#autoAttackModal');
        if (!modalVisible) {
            console.error('FAILURE: Auto Attack modal not visible');
            process.exit(1);
        }

        // Click "Start Attack"
        console.log('Clicking Start Attack...');
        await page.click('#autoAttackStartBtn');

        // Wait for the POST request
        await page.waitForTimeout(2000);

        if (attackStarted) {
            console.log('SUCCESS: Auto Attack launch request verified.');
        } else {
            console.error('FAILURE: Auto Attack launch request was NOT intercepted.');
            process.exit(1);
        }

    } catch (e) {
        console.error('Test Failed:', e);
        process.exit(1);
    } finally {
        await browser.close();
    }
})();
