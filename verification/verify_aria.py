from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # 1. Login
    page.goto("http://localhost:3000")
    page.fill("#username", "admin")
    page.fill("#password", "admin")
    page.click("#loginBtn")

    # Handle force password change if needed
    try:
        # Check if we are redirected to password change form or still on login page with pw change form visible
        page.wait_for_timeout(1000) # Wait for potential redirects/UI updates
        if page.is_visible("#passwordChangeForm"):
            print("Password change required. Changing password...")
            page.fill("#currentPassword", "admin")
            page.fill("#newPassword", "Admin123!")
            page.fill("#confirmPassword", "Admin123!")
            page.click("#pwChangeBtn")
            page.wait_for_url("**/dashboard")
    except:
        pass

    # Wait for dashboard
    page.wait_for_selector("#view-dashboard", timeout=10000)
    print("Dashboard loaded")

    # 2. Open Password Modal
    # The sidebar item for password change
    # <div class="nav-item" onclick="showPasswordModal()">
    page.locator(".nav-item", has_text="Passwort ändern").click()
    print("Clicked Password Change")

    # 3. Wait for modal
    modal = page.locator("#passwordModal")
    expect(modal).to_be_visible()

    # 4. Verify Close Button ARIA Label
    close_btn = modal.locator("button.btn-icon").first
    aria_label = close_btn.get_attribute("aria-label")
    print(f"Close button aria-label: {aria_label}")

    if aria_label != "Schließen":
        print("FAIL: ARIA label is incorrect")
    else:
        print("PASS: ARIA label is correct")

    # 5. Take screenshot
    page.screenshot(path="verification/aria_check.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
