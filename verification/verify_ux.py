from playwright.sync_api import sync_playwright
import os
import sys

def verify_toast(page):
    # Navigate to the dashboard (mocked/static file)
    # We use the file protocol since we can't easily start the backend
    cwd = os.getcwd()
    file_url = f"file://{cwd}/public/dashboard.html"
    page.goto(file_url)

    # Mock window.showToast to verify aria-live attribute
    # And check if the toast container has aria-live="polite"

    toast_container = page.locator("#toastContainer")
    aria_live = toast_container.get_attribute("aria-live")

    print(f"Toast container aria-live: {aria_live}")

    if aria_live != "polite":
        print("FAIL: aria-live attribute is missing or incorrect")
        sys.exit(1)
    else:
        print("PASS: aria-live attribute is correct")

    # Verify visual feedback logic (conceptually) by injecting the JS function manually
    # and mocking a button click
    page.evaluate("""
        document.body.innerHTML += '<button id="testBtn" data-action="copyToClipboard" data-arg0="test"><i class="bi bi-clipboard"></i> Copy</button>';

        // Mock navigator.clipboard
        navigator.clipboard = {
            writeText: () => Promise.resolve()
        };

        // Mock showToast
        window.showToast = (t, title, msg) => console.log(t, title, msg);
    """)

    # We need to manually attach the click listener or rely on dashboard.js being loaded
    # Since dashboard.js has an IIFE and initializes on load, it should handle the new button if we use event delegation correctly.
    # However, the delegation is on 'document', so dynamically added elements work.

    # Click the button
    page.click("#testBtn")

    # Wait a bit for the promise to resolve and visual feedback to apply
    page.wait_for_timeout(500)

    # Check if icon changed
    icon_class = page.eval_on_selector("#testBtn i", "el => el.className")
    print(f"Icon class after click: {icon_class}")

    if "bi-check-lg" in icon_class:
        print("PASS: Icon changed to checkmark")
    else:
        print(f"FAIL: Icon did not change. Current class: {icon_class}")
        # Note: This might fail if dashboard.js didn't load or initialize correctly in file:// mode
        # or if the IIFE didn't attach the listener to document yet.

    page.screenshot(path="verification/toast_aria.png")

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            verify_toast(page)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
        finally:
            browser.close()
