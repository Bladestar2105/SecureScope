const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', exception => console.log('PAGE ERROR:', exception));

  // Helper to take screenshot on failure
  async function takeScreenshot(name) {
      await page.screenshot({ path: `screenshot_${name}.png`, fullPage: true });
  }

  try {
    console.log('Navigating to login page...');
    await page.goto('http://localhost:3000');

    try {
        await Promise.race([
            page.waitForSelector('#loginForm', { state: 'visible', timeout: 5000 }),
            page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 5000 })
        ]);
    } catch (e) {}

    if (await page.isVisible('#loginForm')) {
        console.log('Logging in with admin/admin...');
        await page.fill('#username', 'admin');
        await page.fill('#password', 'admin');
        await page.click('#loginBtn');

        try {
            await Promise.race([
                page.waitForSelector('#loginError:not(.hidden)', { timeout: 3000 }),
                page.waitForSelector('#passwordChangeForm:not(.hidden)', { timeout: 3000 }),
                page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 3000 })
            ]);
        } catch (e) {}

        if (await page.isVisible('#loginError:not(.hidden)')) {
            console.log('Login failed with default creds. Trying new password...');
            await page.fill('#password', 'NewPass123!');
            await page.click('#loginBtn');
            await page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 10000 });
        }
    }

    if (await page.isVisible('#passwordChangeForm:not(.hidden)')) {
         console.log('Password change required (initial login)...');
         await page.fill('#currentPassword', 'admin');
         await page.fill('#newPassword', 'NewPass123!');
         await page.fill('#confirmPassword', 'NewPass123!');
         await page.click('#pwChangeBtn');
         await page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 10000 });
    } else {
        if (!await page.isVisible('#view-dashboard')) {
            await page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 10000 });
        }
    }

    console.log('Dashboard loaded.');

    console.log('Switching to New Scan...');
    await page.click('[data-view="new-scan"]');
    await page.waitForSelector('#view-new-scan.active');

    console.log('Starting scan on 127.0.0.1...');
    await page.fill('#scanTarget', '127.0.0.1');
    await page.selectOption('#scanType', 'quick');
    await page.click('#startScanBtn');

    console.log('Waiting for scan completion (via History)...');
    await page.waitForTimeout(15000);

    console.log('Switching to History...');
    await page.click('[data-view="history"]');
    await page.waitForSelector('#view-history.active');

    try {
        await page.waitForSelector('#historyTableBody tr:has-text("Abgeschlossen")', { timeout: 5000 });
        console.log('Found completed scan in history.');
    } catch (e) {
        console.log('Scan not yet completed in history. Reloading history...');
        await page.evaluate('loadHistory()');
        await page.waitForTimeout(2000);
        await page.waitForSelector('#historyTableBody tr:has-text("Abgeschlossen")', { timeout: 60000 });
        console.log('Found completed scan in history after wait.');
    }

    console.log('Opening scan details...');
    const detailBtn = await page.locator('#historyTableBody tr:has-text("Abgeschlossen") .btn-outline').first();
    await detailBtn.click();

    await page.waitForSelector('#view-scan-detail.active');
    console.log('Scan Detail view active.');
    await takeScreenshot('scan_detail');

    // Verify "Create Chain" button exists in Detail View (use specific selector)
    const createChainBtn = await page.waitForSelector('#view-scan-detail button:has-text("Chain erstellen")', { timeout: 5000 });
    if (!createChainBtn) throw new Error('Create Chain button not found in Detail View');
    console.log('Create Chain button found.');

    console.log('Clicking Create Chain...');
    await createChainBtn.click();

    console.log('Waiting for modal...');
    try {
        await page.waitForSelector('#chainModal.active', { timeout: 10000 });
        console.log('Chain Modal opened.');
        await takeScreenshot('chain_modal');
    } catch (e) {
        console.log('Modal did not open. Checking toasts...');
        if (await page.isVisible('.toast-message')) {
             const toast = await page.textContent('.toast-message');
             console.log('Toast detected:', toast);
        } else {
             console.log('No toast detected either.');
        }
        await takeScreenshot('modal_fail');
        throw e;
    }

    const name = await page.inputValue('#chainFormName');
    console.log(`Chain Name: ${name}`);

    if (!name.includes('Chain from Scan')) throw new Error('Chain name not populated correctly');

    console.log('Saving chain...');
    await page.click('#chainModal .btn-success');

    // Wait for modal to hide
    await page.waitForSelector('#chainModal', { state: 'hidden', timeout: 5000 });
    console.log('Chain saved and modal closed.');

    console.log('Switching to Attack Chains view...');
    await page.click('[data-view="attack-chains"]');
    await page.waitForSelector('#view-attack-chains.active');

    // Wait a bit for the list to refresh (saveChain calls loadAttackChains)
    await page.waitForTimeout(1000);

    await page.waitForSelector('.chain-card h4:has-text("Chain from Scan")', { timeout: 10000 });
    console.log('Chain found in list.');
    await takeScreenshot('chain_list');

    console.log('Test passed successfully.');

  } catch (err) {
    console.error('Test failed:', err);
    await takeScreenshot('failure');
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
