const { chromium } = require('playwright');

(async () => {
    console.log('Starting Verification...');
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

        await page.route('**/api/scan/results/101', async route => {
            await route.fulfill({
                status: 200, body: JSON.stringify({
                    results: [
                        {ip_address:'1.1.1.1', port:80, service:'http', state:'open', service_product: 'Apache'},
                        {ip_address:'1.1.1.1', port:22, service:'ssh', state:'open', service_product: 'OpenSSH'}
                    ]
                })
            });
        });

        // Load Dashboard
        await page.goto('http://localhost:3000/dashboard');
        await page.waitForTimeout(1000);

        // Open Modal
        console.log('Opening modal...');
        await page.evaluate(() => window.showCreateChainForTargetModal(101, '1.1.1.1'));
        await page.waitForTimeout(1000);

        // Screenshot
        console.log('Taking screenshot...');
        await page.screenshot({ path: 'verification/modal_screenshot.png' });

    } catch (e) {
        console.error('Error:', e);
    } finally {
        await browser.close();
    }
})();
