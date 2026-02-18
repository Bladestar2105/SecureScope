const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    console.log('Navigating to login page...');
    await page.goto('http://localhost:3000');
    await page.screenshot({ path: 'screenshot_1_login.png' });

    console.log('Logging in with admin/admin...');
    await page.fill('#username', 'admin');
    await page.fill('#password', 'admin');
    await page.click('#loginBtn');

    // Wait for navigation or password change modal
    // Login might be slow due to hashing
    await page.waitForTimeout(2000);

    // Check if password change is required
    const pwChangeVisible = await page.isVisible('#passwordChangeForm');

    if (pwChangeVisible) {
        console.log('Password change required...');
        await page.screenshot({ path: 'screenshot_2_pwd_change.png' });
        await page.fill('#currentPassword', 'admin');
        await page.fill('#newPassword', 'NewPass123!');
        await page.fill('#confirmPassword', 'NewPass123!');
        await page.click('#pwChangeBtn');

        console.log('Password changed, waiting for redirect...');
        await page.waitForTimeout(2000);
    } else {
        console.log('No password change required (or already changed).');
    }

    console.log('Checking dashboard...');
    try {
        await page.waitForSelector('#view-dashboard', { state: 'visible', timeout: 10000 });
        console.log('Dashboard loaded.');
    } catch (e) {
        console.log('Dashboard selector not found, dumping page content...');
        await page.screenshot({ path: 'screenshot_error_dashboard.png' });
        throw e;
    }

    await page.screenshot({ path: 'screenshot_3_dashboard.png' });

    // Ensure we are on new scan view
    console.log('Switching to New Scan...');
    await page.click('[data-view="new-scan"]');
    await page.waitForSelector('#view-new-scan', { state: 'visible' });
    await page.screenshot({ path: 'screenshot_4_new_scan.png' });

    console.log('Starting scan on 127.0.0.1...');
    await page.fill('#scanTarget', '127.0.0.1');
    await page.selectOption('#scanType', 'quick');
    await page.click('#startScanBtn');

    console.log('Waiting for scan to start...');
    try {
        await page.waitForSelector('#scanProgressPanel:not(.hidden)', { timeout: 5000 });
        console.log('Scan started successfully.');
    } catch (e) {
        console.log('Scan progress panel not visible.');
        // Maybe error toast?
        await page.screenshot({ path: 'screenshot_error_scan.png' });
        throw e;
    }

    await page.screenshot({ path: 'screenshot_5_scan_started.png' });

    // Wait for some progress
    console.log('Waiting for progress...');
    await page.waitForTimeout(5000);
    await page.screenshot({ path: 'screenshot_6_scan_progress.png' });

    console.log('Stopping scan...');
    await page.click('#stopScanBtn');
    await page.waitForTimeout(1000);
    await page.screenshot({ path: 'screenshot_7_scan_stopped.png' });

    console.log('Logging out...');
    await page.click('[title="Abmelden"]');
    await page.waitForSelector('#loginForm', { timeout: 5000 });
    console.log('Logged out successfully.');
    await page.screenshot({ path: 'screenshot_8_logged_out.png' });

  } catch (err) {
    console.error('Test failed:', err);
    await page.screenshot({ path: 'screenshot_error_final.png' });
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
