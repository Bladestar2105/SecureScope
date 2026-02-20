const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    console.log('Navigating to login page...');
    await page.goto('http://localhost:3000');

    // Check if password input exists
    const passwordInput = await page.$('#password');
    if (!passwordInput) throw new Error('Password input not found');
    console.log('Password input found.');

    // Check if password type is initially "password"
    let type = await passwordInput.getAttribute('type');
    if (type !== 'password') throw new Error(`Initial password type is ${type}, expected 'password'`);
    console.log('Initial password type is correct.');

    // Check for toggle button
    // It shouldn't exist yet (this test is expected to fail initially if I run it before changes)
    // But I will run it after changes.
    // For now, let's write the test assuming the button has class 'password-toggle'

    // Search for button inside the input group of the password field
    // Since I'm adding it next to the password input, I can look for a button sibling or just generic query
    const toggleBtn = await page.$('#togglePassword');

    if (!toggleBtn) {
        console.log('Toggle button not found (Expected before implementation)');
        // If I want this script to be used for verification, I should fail if not found.
        throw new Error('Toggle button not found');
    }
    console.log('Toggle button found.');

    // Click to show password
    await toggleBtn.click();

    // Check type is 'text'
    type = await passwordInput.getAttribute('type');
    if (type !== 'text') throw new Error(`After click, password type is ${type}, expected 'text'`);
    console.log('Password type changed to text.');

    // Check icon changed to eye-slash (optional, but good UX)
    // I plan to use bi-eye-slash when visible
    const icon = await toggleBtn.$('i');
    const iconClass = await icon.getAttribute('class');
    if (!iconClass.includes('bi-eye-slash')) console.warn('Icon did not change to eye-slash (check implementation)');
    else console.log('Icon changed to eye-slash.');

    // Click to hide password
    await toggleBtn.click();

    // Check type is 'password'
    type = await passwordInput.getAttribute('type');
    if (type !== 'password') throw new Error(`After second click, password type is ${type}, expected 'password'`);
    console.log('Password type changed back to password.');

    console.log('UX TEST PASSED');

  } catch (err) {
    console.error('Test failed:', err);
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
