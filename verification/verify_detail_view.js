const { chromium } = require('playwright');

(async () => {
    console.log('Starting Detail View Verification...');
    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();

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

        await page.route('**/api/scan/101', async route => {
            await route.fulfill({
                status: 200, body: JSON.stringify({
                    scan: { id: 101, target: '1.1.1.1', status: 'completed', started_at: '2023-01-01', completed_at: '2023-01-01' },
                    results: [
                        {ip_address:'1.1.1.1', port:80, service:'http', state:'open', service_product: 'Apache'},
                        {ip_address:'1.1.1.1', port:22, service:'ssh', state:'open', service_product: 'OpenSSH'}
                    ]
                })
            });
        });

        await page.route('**/api/scan/cves/101', async route => {
             await route.fulfill({ status: 200, body: JSON.stringify({ cves: [] }) });
        });

        // Load Dashboard
        await page.goto('http://localhost:3000/dashboard');
        await page.waitForTimeout(1000);

        // Trigger viewScanDetail(101) directly
        console.log('Opening Detail View...');
        await page.evaluate(() => window.viewScanDetail(101));
        await page.waitForTimeout(1000);

        // Check for the "Chain erstellen" button in the detail view results body
        // using a more specific selector
        const button = await page.locator('#detailResultsBody button:has-text("Chain erstellen")').first();

        if (await button.isVisible()) {
            console.log('SUCCESS: "Chain erstellen" button is visible in detail view.');
        } else {
            console.log('FAILURE: "Chain erstellen" button is NOT visible in detail view.');
            process.exit(1);
        }

        // Screenshot
        console.log('Taking screenshot...');
        await page.screenshot({ path: 'verification/detail_view_verification.png' });

    } catch (e) {
        console.error('Error:', e);
        process.exit(1);
    } finally {
        await browser.close();
    }
})();
