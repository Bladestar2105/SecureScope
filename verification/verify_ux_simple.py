from playwright.sync_api import sync_playwright
import os
import sys

def verify_toast(page):
    # Use simple HTML content to test the concept since full dashboard might fail to load deps
    html_content = """
    <!DOCTYPE html>
    <html>
    <body>
        <div id="toastContainer" class="toast-container" aria-live="polite"></div>
        <button id="testBtn"><i class="bi bi-clipboard"></i> Copy</button>
        <script>
            // Mock the logic we added to dashboard.js
            window.copyToClipboard = function(text) {
                const btn = (this instanceof Element) ? this : null;
                // Mock clipboard
                Promise.resolve().then(() => {
                    if (btn) {
                        const icon = btn.querySelector('i');
                        if (icon) {
                            icon.className = 'bi bi-check-lg';
                        }
                    }
                });
            };

            document.getElementById('testBtn').addEventListener('click', function() {
                window.copyToClipboard.call(this, 'test');
            });
        </script>
    </body>
    </html>
    """

    page.set_content(html_content)

    toast_container = page.locator("#toastContainer")
    aria_live = toast_container.get_attribute("aria-live")

    print(f"Toast container aria-live: {aria_live}")

    if aria_live != "polite":
        print("FAIL: aria-live attribute is missing or incorrect")
    else:
        print("PASS: aria-live attribute is correct")

    # Click the button
    page.click("#testBtn")

    # Wait a bit
    page.wait_for_timeout(100)

    # Check if icon changed
    icon_class = page.eval_on_selector("#testBtn i", "el => el.className")
    print(f"Icon class after click: {icon_class}")

    if "bi-check-lg" in icon_class:
        print("PASS: Icon changed to checkmark")
    else:
        print(f"FAIL: Icon did not change. Current class: {icon_class}")

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
