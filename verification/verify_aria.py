import time
import os
import subprocess
import threading
from playwright.sync_api import sync_playwright

def start_server():
    # Start a simple HTTP server on port 8000
    subprocess.Popen(["python3", "-m", "http.server", "8000"], cwd="/app/public", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

def verify_aria(page):
    # Mock APIs
    page.route("**/api/auth/status", lambda route: route.fulfill(json={"authenticated": True, "user": {"id": 1, "username": "admin", "roles": ["admin"]}, "csrfToken": "test"}))
    page.route("**/api/scan/dashboard", lambda route: route.fulfill(json={"totalScans": 10, "completedScans": 5, "activeScans": 0, "recentScans": []}))

    # Mock History
    page.route("**/api/scan/history", lambda route: route.fulfill(json={"scans": [
        {"id": 101, "target": "192.168.1.1", "scan_type": "quick", "status": "completed", "result_count": 5, "vuln_count": 0, "started_at": "2024-01-01T12:00:00Z"}
    ]}))

    # Mock Schedules
    page.route("**/api/schedules", lambda route: route.fulfill(json={"schedules": [
        {"id": 201, "name": "Daily Scan", "target": "10.0.0.1", "scan_type": "full", "cron_expression": "0 0 * * *", "enabled": True, "next_run": "2024-01-02T00:00:00Z"}
    ]}))

    # Mock Users
    page.route("**/api/users", lambda route: route.fulfill(json={"users": [
        {"id": 301, "username": "testuser", "roles": ["user"], "last_login": "2024-01-01T10:00:00Z", "created_at": "2023-12-01T00:00:00Z"}
    ]}))

    # Navigate
    page.goto("http://localhost:8000/dashboard.html")

    # Wait for dashboard to load
    page.wait_for_selector("#view-dashboard")

    print("Dashboard loaded.")

    # 1. Verify History Buttons
    print("Checking History buttons...")
    page.evaluate("switchView('history')")
    page.wait_for_selector("#historyTableBody tr")

    view_btn = page.locator('button[data-action="viewScanDetail"][aria-label="Details anzeigen"]')
    delete_btn = page.locator('button[data-action="deleteScan"][aria-label="Scan löschen"]')

    if view_btn.count() > 0:
        print("PASS: Found 'Details anzeigen' button in history.")
    else:
        print("FAIL: 'Details anzeigen' button not found in history.")

    if delete_btn.count() > 0:
        print("PASS: Found 'Scan löschen' button in history.")
    else:
        print("FAIL: 'Scan löschen' button not found in history.")

    # 2. Verify Schedules Buttons
    print("Checking Schedules buttons...")
    page.evaluate("switchView('schedules')")
    page.wait_for_selector("#schedulesTableBody tr")

    toggle_btn = page.locator('button[data-action="toggleSchedule"][aria-label="Zeitplan pausieren"]')
    del_sched_btn = page.locator('button[data-action="deleteSchedule"][aria-label="Zeitplan löschen"]')

    if toggle_btn.count() > 0:
        print("PASS: Found 'Zeitplan pausieren' button.")
    else:
        print("FAIL: 'Zeitplan pausieren' button not found.")

    if del_sched_btn.count() > 0:
        print("PASS: Found 'Zeitplan löschen' button.")
    else:
        print("FAIL: 'Zeitplan löschen' button not found.")

    # 3. Verify Users Buttons
    print("Checking Users buttons...")
    page.evaluate("switchView('users')")
    page.wait_for_selector("#usersTableBody tr")

    del_user_btn = page.locator('button[data-action="deleteUser"][aria-label="Benutzer löschen"]')

    if del_user_btn.count() > 0:
        print("PASS: Found 'Benutzer löschen' button.")
    else:
        print("FAIL: 'Benutzer löschen' button not found.")

    # Screenshot for visual proof (even if labels are invisible)
    page.screenshot(path="verification/verification.png")
    print("Screenshot saved to verification/verification.png")

if __name__ == "__main__":
    start_server()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            verify_aria(page)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            browser.close()
            # Kill server (rough way)
            os.system("pkill -f 'python3 -m http.server'")

