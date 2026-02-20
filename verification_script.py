from playwright.sync_api import sync_playwright
import time
import json

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.route("**/api/auth/status", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"authenticated": true, "user": {"username": "admin", "forcePasswordChange": false}, "csrfToken": "test"}'
        ))

        scan_response = {
            "scan": {
                "id": 123,
                "target": "192.168.1.1",
                "scan_type": "full",
                "status": "completed",
                "started_at": "2023-10-27T10:00:00Z",
                "completed_at": "2023-10-27T10:05:00Z",
                "port_range": "1-65535"
            },
            "results": [
                {
                    "ip_address": "192.168.1.1",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "banner": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f This is a very long banner that should be truncated because it is too long for the table cell and might break the layout if not handled correctly.",
                    "service_product": "Apache httpd",
                    "service_version": "2.4.41",
                    "state": "open",
                    "risk_level": "low",
                    "os_name": "Linux 5.4"
                }
            ]
        }

        page.route("**/api/scan/123", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(scan_response)
        ))

        page.route("**/api/scan/cves/123", lambda route: route.fulfill(status=200, content_type="application/json", body='{"cves": []}'))
        page.route("**/api/scan/dashboard", lambda route: route.fulfill(status=200, content_type="application/json", body='{}'))
        page.route("**/api/scan/events", lambda route: route.fulfill(status=200, content_type="text/event-stream", body=''))

        page.goto("http://localhost:8080/dashboard.html")
        time.sleep(1)
        page.evaluate("window.viewScanDetail(123)")
        time.sleep(1)
        page.screenshot(path="verification.png")
        browser.close()

if __name__ == "__main__":
    run()
