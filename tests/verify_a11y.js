const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    console.log('Navigating to login page...');
    await page.goto('http://localhost:3000');

    // Login
    await page.fill('#username', 'admin');
    await page.fill('#password', 'admin');
    await page.click('#loginBtn');

    // Handle password change if needed
    try {
        await page.waitForSelector('#passwordChangeForm', { state: 'visible', timeout: 2000 });
        console.log('Password change required...');
        await page.fill('#currentPassword', 'admin');
        await page.fill('#newPassword', 'NewPass123!');
        await page.fill('#confirmPassword', 'NewPass123!');
        await page.click('#pwChangeBtn');
        await page.waitForTimeout(2000);
    } catch (e) {
        // No password change needed
    }

    await page.waitForSelector('#view-dashboard');
    console.log('Dashboard loaded.');

    // 1. Check Skip Link Existence
    const skipLink = await page.$('.skip-link');
    if (!skipLink) throw new Error('Skip link not found!');
    console.log('Skip link found.');

    // Verify it points to main content
    const href = await skipLink.getAttribute('href');
    if (href !== '#main-content') throw new Error('Skip link href is wrong: ' + href);

    // Verify main content has id
    const mainContent = await page.$('#main-content');
    if (!mainContent) throw new Error('#main-content not found!');

    // 2. Check Visibility on Focus
    await skipLink.focus();
    // Wait for transition
    await page.waitForTimeout(300);
    const focusedTop = await skipLink.evaluate(el => window.getComputedStyle(el).top);
    if (focusedTop !== '0px') throw new Error('Skip link not visible on focus! top=' + focusedTop);
    console.log('Skip link visible on focus.');

    // 3. Check Focus Management on View Switch
    console.log('Switching to History view...');
    await page.click('[data-view="history"]');

    // Wait for JS to execute
    await page.waitForTimeout(500);

    const focusedId = await page.evaluate(() => document.activeElement.id);
    if (focusedId !== 'viewTitle') {
        const activeElem = await page.evaluate(() => document.activeElement.tagName);
        throw new Error(`Focus did not move to viewTitle! Focused element ID: ${focusedId}, Tag: ${activeElem}`);
    }
    console.log('Focus moved to viewTitle successfully.');

    console.log('ALL TESTS PASSED');

  } catch (err) {
    console.error('Test failed:', err);
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
