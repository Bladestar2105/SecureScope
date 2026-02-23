from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()

    # Log console messages to catch JS errors
    page.on("console", lambda msg: print(f"CONSOLE: {msg.text}"))
    page.on("pageerror", lambda err: print(f"PAGE ERROR: {err}"))

    # Mock API responses
    page.route("**/api/auth/status", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"authenticated": false, "csrfToken": "test-token"}'
    ))

    page.route("**/api/auth/login", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"success": true, "user": {"username": "admin", "forcePasswordChange": false}, "csrfToken": "new-token"}'
    ))

    print("Navigating to login page...")
    page.goto("http://localhost:3000/index.html")

    # Verify elements are present (this confirms JS didn't crash)
    print("Verifying login form...")
    page.wait_for_selector("#loginForm")

    # Fill form
    page.fill("#username", "admin")
    page.fill("#password", "admin")

    # Click login (this tests if the event listener was attached correctly)
    print("Clicking login...")
    page.click("#loginBtn")

    # Wait for success toast (added dynamically via JS)
    try:
        page.wait_for_selector(".toast-success", timeout=5000)
        print("SUCCESS: Login toast appeared!")
    except Exception as e:
        print("FAILURE: Login toast did not appear. JS might be broken.")
        page.screenshot(path="verification_failure.png")
        browser.close()
        exit(1)

    # Take success screenshot
    page.screenshot(path="verification_success.png")
    print("Screenshot saved to verification_success.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
