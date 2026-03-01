1. **Goal**: Add the password visibility toggle (the `.password-toggle` class) to the password fields in `public/dashboard.html` and add the logic in `public/js/dashboard.js` to handle the toggling.

2. **Actions in `public/dashboard.html`**:
   - For SMTP password (`#smtpPass`), Credential password (`#credPassword`), Current Password (`#modalCurrentPw`), New Password (`#modalNewPw`), Confirm Password (`#modalConfirmPw`), and User Form Password (`#userFormPass`):
     - Wrap the `input` in `<div class="input-group">`.
     - Add the visibility toggle button after the input.
     - Add the input icon if appropriate.

3. **Actions in `public/js/dashboard.js`**:
   - Add the logic to handle `.password-toggle` clicks (similar to `login.js`), toggling the input type between `password` and `text` and swapping the `bi-eye` and `bi-eye-slash` icons. Since `dashboard.js` dynamically adds/removes UI or uses event delegation, we should ideally use event delegation for this on the document, or add a specific listener in `init()`.
