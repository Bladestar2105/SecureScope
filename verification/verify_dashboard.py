from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()

    page.on("console", lambda msg: print(f"CONSOLE: {msg.text}"))
    page.on("pageerror", lambda err: print(f"PAGE ERROR: {err}"))

    # Mock APIs
    page.route("**/api/auth/status", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"authenticated": true, "user": {"username": "admin", "forcePasswordChange": false}, "csrfToken": "abc"}'
    ))
    page.route("**/api/users/me/permissions", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"roles": ["admin"], "permissions": []}'
    ))
    page.route("**/api/scan/dashboard", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"totalScans": 10, "completedScans": 8, "criticalPorts": 2, "totalVulnerabilities": 5, "activeScans": 0}'
    ))
    page.route("**/api/scan/events", lambda route: route.fulfill(
        status=200,
        content_type="text/event-stream",
        body=""
    ))

    print("Navigating to dashboard...")
    page.goto("http://localhost:3000/dashboard.html")

    print("Verifying dashboard elements...")
    try:
        page.wait_for_selector("#view-dashboard", timeout=5000)
        print("Dashboard loaded.")
    except:
        print("Dashboard failed to load.")
        page.screenshot(path="dashboard_failure.png")
        browser.close()
        exit(1)

    # Check if stats are rendered
    total_scans = page.locator("#statTotalScans").text_content()
    print(f"Total Scans: {total_scans}")
    if total_scans != "10":
        print("Stats not rendered correctly.")
        exit(1)

    page.screenshot(path="dashboard_success.png")
    print("Screenshot saved to dashboard_success.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
