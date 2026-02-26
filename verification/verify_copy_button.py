from playwright.sync_api import sync_playwright
import time

def run(playwright):
    browser = playwright.chromium.launch()
    context = browser.new_context()
    page = context.new_page()

    # Mock API routes
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
        body='{"totalScans": 1, "completedScans": 1, "criticalPorts": 0, "totalVulnerabilities": 0, "activeScans": 0, "recentScans": [{"id": 123, "target": "192.168.1.100", "scan_type": "quick", "status": "completed", "result_count": 1, "vuln_count": 0, "started_at": "2023-10-27T10:00:00Z"}]}'
    ))

    page.route("**/api/scan/123", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"scan": {"id": 123, "target": "192.168.1.100", "scan_type": "quick", "status": "completed", "started_at": "2023-10-27T10:00:00Z", "completed_at": "2023-10-27T10:05:00Z"}, "results": [{"ip_address": "192.168.1.100", "port": 80, "protocol": "tcp", "service": "http", "state": "open", "risk_level": "low", "os_name": "Linux"}]}'
    ))

    page.route("**/api/scan/cves/123", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"cves": []}'
    ))

    # Go to dashboard
    page.goto("http://localhost:8080/dashboard.html")

    # Wait for dashboard to load
    page.wait_for_selector("#recentScansTableBody tr")

    # Click on the "eye" icon to view details
    page.click("button[data-action='viewScanDetail']")

    # Wait for detail view to load and our button to appear
    # The button has aria-label="IP kopieren"
    page.wait_for_selector("button[aria-label='IP kopieren']")

    # Take screenshot
    page.screenshot(path="verification/copy_button.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
