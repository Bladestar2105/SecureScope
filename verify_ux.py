
import asyncio
from playwright.async_api import async_playwright, expect

async def verify_dashboard():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Mock API calls
        await page.route("**/api/auth/status", lambda route: route.fulfill(
            status=200,
            body='{"authenticated": true, "user": {"username": "admin", "id": 1, "roles": ["admin"]}, "csrfToken": "test"}'
        ))

        await page.route("**/api/users/me/permissions", lambda route: route.fulfill(
            status=200,
            body='{"roles": ["admin"], "permissions": []}'
        ))

        await page.route("**/api/scan/dashboard", lambda route: route.fulfill(
            status=200,
            body='{"totalScans": 10, "completedScans": 8, "criticalPorts": 2, "totalVulnerabilities": 5, "activeScans": 1, "recentScans": [{"id": 1, "target": "192.168.1.10", "scan_type": "quick", "status": "completed", "result_count": 5, "vuln_count": 0, "started_at": "2023-10-27T10:00:00Z"}]}'
        ))

        await page.route("**/api/scan/history", lambda route: route.fulfill(
            status=200,
            body='{"scans": [{"id": 1, "target": "192.168.1.10", "scan_type": "quick", "status": "completed", "result_count": 5, "vuln_count": 0, "started_at": "2023-10-27T10:00:00Z"}]}'
        ))

        await page.route("**/api/fingerprints*", lambda route: route.fulfill(
            status=200,
            body='{"fingerprints": [{"id": 1, "port": 22, "service_name": "ssh", "version_pattern": "OpenSSH 8.2", "os_family": "Linux", "cpe": "cpe:/a:openbsd:openssh:8.2", "confidence": 90, "source": "nmap-db"}], "pagination": {"page": 1, "totalPages": 1, "total": 1}}'
        ))

        await page.route("**/api/exploits*", lambda route: route.fulfill(
            status=200,
            body='{"exploits": [{"id": 1, "exploit_db_id": "EDB-12345", "cve_id": "CVE-2023-1234", "title": "Test Exploit", "severity": "critical", "cvss_score": 9.8, "platform": "Linux", "exploit_type": "remote", "reliability": "excellent", "source": "exploit-db", "exploit_code": "code"}], "pagination": {"page": 1, "totalPages": 1, "total": 1}}'
        ))

        await page.route("**/api/schedules", lambda route: route.fulfill(
            status=200,
            body='{"schedules": [{"id": 1, "name": "Daily Scan", "target": "192.168.1.0/24", "scan_type": "standard", "cron_expression": "0 0 * * *", "enabled": true, "next_run": "2023-10-28T00:00:00Z"}]}'
        ))

        await page.route("**/api/users", lambda route: route.fulfill(
            status=200,
            body='{"users": [{"id": 2, "username": "user", "roles": ["user"], "last_login": "2023-10-27T09:00:00Z", "created_at": "2023-10-01T00:00:00Z"}]}'
        ))

        await page.route("**/api/attack-chains", lambda route: route.fulfill(
            status=200,
            body='{"chains": [{"id": 1, "name": "Test Chain", "description": "Test", "strategy": "standard", "enabled": true, "risk_level": "medium", "max_depth": 2, "steps": [{"name": "Step 1"}]}]}'
        ))

        await page.route("**/api/attack-chains/executions/history", lambda route: route.fulfill(
            status=200,
            body='{"executions": [{"id": 1, "chain_name": "Test Chain", "target_scan_id": 1, "status": "completed", "steps_completed": 1, "steps_total": 1, "started_at": "2023-10-27T10:30:00Z"}]}'
        ))

        await page.route("**/api/audits", lambda route: route.fulfill(
            status=200,
            body='{"audits": [{"id": 1, "scan_id": 1, "audit_type": "full", "overall_score": 85, "risk_rating": "low", "findings_count": 2, "generated_at": "2023-10-27T11:00:00Z"}]}'
        ))

        # Navigate to Dashboard
        print("Navigating to Dashboard...")
        try:
            await page.goto("http://localhost:8080/dashboard.html", timeout=10000)
        except Exception as e:
            print(f"Navigation error: {e}")
            await browser.close()
            return

        # Wait for data to load
        print("Waiting for data to load...")
        await page.wait_for_selector("#recentScansTableBody tr")

        # --- Verify Dashboard (Recent Scans) ---
        print("Verifying Dashboard...")
        recent_scans_btn = page.locator("#recentScansTableBody button[onclick^='viewScanDetail']")
        await expect(recent_scans_btn).to_be_visible()
        aria_label = await recent_scans_btn.get_attribute("aria-label")
        print(f"Recent Scans Button Aria-Label: {aria_label}")
        if aria_label != "Details zu Scan #1":
             print("ERROR: Dashboard button aria-label mismatch!")

        # Take screenshot of Dashboard
        await page.screenshot(path="verification_dashboard.png")

        # --- Verify History ---
        print("Verifying History...")
        await page.evaluate("switchView('history')")
        await page.wait_for_selector("#historyTableBody tr")

        history_view_btn = page.locator("#historyTableBody button[onclick^='viewScanDetail']")
        history_del_btn = page.locator("#historyTableBody button[onclick^='deleteScan']")

        await expect(history_view_btn).to_be_visible()
        await expect(history_del_btn).to_be_visible()

        aria_label_view = await history_view_btn.get_attribute("aria-label")
        aria_label_del = await history_del_btn.get_attribute("aria-label")

        print(f"History View Button Aria-Label: {aria_label_view}")
        print(f"History Delete Button Aria-Label: {aria_label_del}")

        if aria_label_view != "Details zu Scan #1": print("ERROR: History View button aria-label mismatch!")
        if aria_label_del != "Scan #1 löschen": print("ERROR: History Delete button aria-label mismatch!")

        # Take screenshot of History
        await page.screenshot(path="verification_history.png")

        # --- Verify Fingerprints ---
        print("Verifying Fingerprints...")
        await page.evaluate("switchView('fingerprints')")
        await page.wait_for_selector("#fpTableBody tr")

        fp_view_btn = page.locator("#fpTableBody button[onclick^='showFingerprintDetail']")
        fp_del_btn = page.locator("#fpTableBody button[onclick^='deleteFingerprint']")

        aria_label_fp_view = await fp_view_btn.get_attribute("aria-label")
        aria_label_fp_del = await fp_del_btn.get_attribute("aria-label")

        print(f"Fingerprint View Button Aria-Label: {aria_label_fp_view}")
        print(f"Fingerprint Delete Button Aria-Label: {aria_label_fp_del}")

        # --- Verify Exploits ---
        print("Verifying Exploits...")
        await page.evaluate("switchView('exploits')")
        await page.wait_for_selector("#exploitTableBody tr")

        ex_view_btn = page.locator("#exploitTableBody button[onclick^='showExploitDetail']")
        ex_code_btn = page.locator("#exploitTableBody button[onclick^='showExploitCode']")
        ex_del_btn = page.locator("#exploitTableBody button[onclick^='deleteExploit']")

        print(f"Exploit View Button Aria-Label: {await ex_view_btn.get_attribute('aria-label')}")
        print(f"Exploit Code Button Aria-Label: {await ex_code_btn.get_attribute('aria-label')}")
        print(f"Exploit Delete Button Aria-Label: {await ex_del_btn.get_attribute('aria-label')}")

        # --- Verify Schedules ---
        print("Verifying Schedules...")
        await page.evaluate("switchView('schedules')")
        await page.wait_for_selector("#schedulesTableBody tr")

        sched_toggle_btn = page.locator("#schedulesTableBody button[onclick^='toggleSchedule']")
        sched_del_btn = page.locator("#schedulesTableBody button[onclick^='deleteSchedule']")

        print(f"Schedule Toggle Button Aria-Label: {await sched_toggle_btn.get_attribute('aria-label')}")
        print(f"Schedule Delete Button Aria-Label: {await sched_del_btn.get_attribute('aria-label')}")

        # --- Verify Users ---
        print("Verifying Users...")
        await page.evaluate("switchView('users')")
        await page.wait_for_selector("#usersTableBody tr")

        user_del_btn = page.locator("#usersTableBody button[onclick^='deleteUser']")
        print(f"User Delete Button Aria-Label: {await user_del_btn.get_attribute('aria-label')}")

        # --- Verify Attack Chains ---
        print("Verifying Attack Chains...")
        await page.evaluate("switchView('attack-chains')")
        await page.wait_for_selector("#chainsTableBody .chain-card")

        chain_del_btn = page.locator("#chainsTableBody button[onclick^='deleteChain']")
        print(f"Chain Delete Button Aria-Label: {await chain_del_btn.get_attribute('aria-label')}")

        # --- Verify Audits ---
        print("Verifying Audits...")
        await page.evaluate("switchView('audits')")
        await page.wait_for_selector("#auditHistoryBody tr")

        audit_del_btn = page.locator("#auditHistoryBody button[onclick^='deleteAudit']")
        print(f"Audit Delete Button Aria-Label: {await audit_del_btn.get_attribute('aria-label')}")


        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify_dashboard())
