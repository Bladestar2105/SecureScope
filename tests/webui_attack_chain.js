const { chromium } = require('playwright');
const assert = require('assert');

(async () => {
    console.log('Starting WebUI Attack Chain Test...');
    const browser = await chromium.launch({ args: ['--no-sandbox'] });
    const context = await browser.newContext();
    const page = await context.newPage();

    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
    page.on('pageerror', exception => console.log(`PAGE ERROR: "${exception}"`));
    // page.on('request', request => console.log('>>', request.method(), request.url()));
    // page.on('response', response => console.log('<<', response.status(), response.url()));

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
                status: 200, body: JSON.stringify({ results: [{ip_address:'1.1.1.1', port:80, service:'http', state: 'open'}] })
            });
        });

        await page.route('**/api/exploits/scan/101', async route => {
            await route.fulfill({
                status: 200, body: JSON.stringify({
                    exploits: [{
                        exploit_id: 1,
                        exploit_title: 'Test Exploit',
                        match_confidence: 100,
                        port: 80,
                        ip_address: '1.1.1.1',
                        exploit_db_id: '12345'
                    }]
                })
            });
        });

        // 2. Load Dashboard
        console.log('Loading dashboard...');
        await page.goto('http://localhost:3000/dashboard');
        await page.waitForTimeout(2000);

        // 3. Trigger "Create Chain for Target"
        console.log('Triggering showCreateChainForTargetModal(101, "1.1.1.1")...');

        const type = await page.evaluate(() => typeof window.showCreateChainForTargetModal);
        console.log('Type of window.showCreateChainForTargetModal:', type);

        if (type === 'function') {
            // Open modal
            await page.evaluate(() => window.showCreateChainForTargetModal(101, '1.1.1.1'));
            await page.waitForTimeout(500);

            // Verify modal is active and service is present
            const modalVisible = await page.isVisible('#chainTargetModal');
            if (!modalVisible) {
                console.log('FAILURE: Target modal not visible');
                process.exit(1);
            }

            // Check if checkbox is rendered (id chk_svc_80)
            const checkbox = await page.locator('#chk_svc_80');
            if (await checkbox.count() > 0) {
                console.log('SUCCESS: Service checkbox found');
            } else {
                console.log('FAILURE: Service checkbox NOT found');
                process.exit(1);
            }

            // Click "Create Chain" in the modal
            console.log('Clicking Create Chain...');
            await page.evaluate(() => window.createChainFromTarget());
            await page.waitForTimeout(1000);

            // Check input values in the main chain modal
            const inputs = await page.locator('#chainStepsContainer input[data-field="name"]').all();
            let found = false;
            for (const input of inputs) {
                const val = await input.inputValue();
                console.log('Step Name:', val);
                if (val.includes('Test Exploit')) found = true;
            }

            if (found) {
                console.log('SUCCESS: Exploit found in generated chain inputs');
            } else {
                console.log('FAILURE: Exploit not found in generated chain inputs');
                process.exit(1);
            }
        } else {
            console.log('FAILURE: Function not found.');
            process.exit(1);
        }

    } catch (e) {
        console.error('Test Failed:', e);
        process.exit(1);
    } finally {
        await browser.close();
    }
})();
