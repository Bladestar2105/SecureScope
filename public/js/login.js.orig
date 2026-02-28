// ============================================
// SecureScope - Login Page JavaScript
// ============================================

(function () {
    'use strict';

    let csrfToken = null;

    // DOM Elements
    const loginForm = document.getElementById('loginForm');
    const passwordChangeForm = document.getElementById('passwordChangeForm');
    const loginError = document.getElementById('loginError');
    const pwChangeError = document.getElementById('pwChangeError');
    const loginBtn = document.getElementById('loginBtn');
    const loginBtnText = document.getElementById('loginBtnText');
    const loginSpinner = document.getElementById('loginSpinner');
    const pwChangeBtn = document.getElementById('pwChangeBtn');
    const pwChangeBtnText = document.getElementById('pwChangeBtnText');
    const pwChangeSpinner = document.getElementById('pwChangeSpinner');

    // Password requirement elements
    const newPasswordInput = document.getElementById('newPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const reqLength = document.getElementById('reqLength');
    const reqUpper = document.getElementById('reqUpper');
    const reqLower = document.getElementById('reqLower');
    const reqNumber = document.getElementById('reqNumber');
    const reqMatch = document.getElementById('reqMatch');

    // ============================================
    // Toast Notification System
    // ============================================
    function showToast(type, title, message) {
        const container = document.getElementById('toastContainer');
        const icons = {
            success: 'bi-check-circle-fill',
            error: 'bi-x-circle-fill',
            warning: 'bi-exclamation-triangle-fill',
            info: 'bi-info-circle-fill'
        };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <i class="bi ${icons[type]} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" aria-label="Benachrichtigung schließen">
                <i class="bi bi-x"></i>
            </button>
        `;

        container.appendChild(toast);

        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        });

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('removing');
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    }

    // ============================================
    // API Helper
    // ============================================
    async function apiRequest(url, method = 'GET', body = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        };

        if (csrfToken) {
            options.headers['X-CSRF-Token'] = csrfToken;
        }

        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(url, options);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Ein Fehler ist aufgetreten');
        }

        return data;
    }

    // ============================================
    // Check Session Status
    // ============================================
    async function checkSession() {
        try {
            const data = await apiRequest('/api/auth/status');

            // Store CSRF token even if not authenticated
            if (data.csrfToken) {
                csrfToken = data.csrfToken;
            }

            if (data.authenticated) {
                if (data.user.forcePasswordChange) {
                    csrfToken = data.csrfToken;
                    showPasswordChangeForm();
                } else {
                    window.location.href = '/dashboard';
                }
            }
        } catch (err) {
            // Not authenticated, stay on login page
        }
    }

    // ============================================
    // Login Handler
    // ============================================
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            showError(loginError, 'Bitte füllen Sie alle Felder aus');
            return;
        }

        setLoading(loginBtn, loginBtnText, loginSpinner, true);
        hideError(loginError);

        try {
            const data = await apiRequest('/api/auth/login', 'POST', { username, password });

            if (data.success) {
                csrfToken = data.csrfToken;

                if (data.user.forcePasswordChange) {
                    showToast('warning', 'Passwortänderung', 'Bitte ändern Sie Ihr Standard-Passwort');
                    showPasswordChangeForm();
                } else {
                    showToast('success', 'Angemeldet', `Willkommen, ${data.user.username}!`);
                    setTimeout(() => {
                        window.location.href = '/dashboard';
                    }, 500);
                }
            }
        } catch (err) {
            showError(loginError, err.message);
            showToast('error', 'Login fehlgeschlagen', err.message);
        } finally {
            setLoading(loginBtn, loginBtnText, loginSpinner, false);
        }
    });

    // ============================================
    // Password Change Handler
    // ============================================
    passwordChangeForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        if (!currentPassword || !newPassword || !confirmPassword) {
            showError(pwChangeError, 'Bitte füllen Sie alle Felder aus');
            return;
        }

        if (newPassword !== confirmPassword) {
            showError(pwChangeError, 'Passwörter stimmen nicht überein');
            return;
        }

        if (newPassword.length < 8) {
            showError(pwChangeError, 'Passwort muss mindestens 8 Zeichen lang sein');
            return;
        }

        setLoading(pwChangeBtn, pwChangeBtnText, pwChangeSpinner, true);
        hideError(pwChangeError);

        try {
            const data = await apiRequest('/api/auth/change-password', 'POST', {
                currentPassword,
                newPassword,
                confirmPassword
            });

            if (data.success) {
                showToast('success', 'Passwort geändert', 'Ihr Passwort wurde erfolgreich geändert');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            }
        } catch (err) {
            showError(pwChangeError, err.message);
            showToast('error', 'Fehler', err.message);
        } finally {
            setLoading(pwChangeBtn, pwChangeBtnText, pwChangeSpinner, false);
        }
    });

    // ============================================
    // Password Validation (Real-time)
    // ============================================
    function validatePasswordRequirements() {
        const password = newPasswordInput.value;
        const confirm = confirmPasswordInput.value;

        toggleRequirement(reqLength, password.length >= 8);
        toggleRequirement(reqUpper, /[A-Z]/.test(password));
        toggleRequirement(reqLower, /[a-z]/.test(password));
        toggleRequirement(reqNumber, /\d/.test(password));
        toggleRequirement(reqMatch, password.length > 0 && password === confirm);
    }

    function toggleRequirement(element, met) {
        if (met) {
            element.classList.add('met');
        } else {
            element.classList.remove('met');
        }
    }

    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', validatePasswordRequirements);
    }
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', validatePasswordRequirements);
    }

    // ============================================
    // UI Helpers
    // ============================================
    function showPasswordChangeForm() {
        loginForm.classList.add('hidden');
        passwordChangeForm.classList.remove('hidden');
        document.getElementById('currentPassword').focus();
    }

    function showError(element, message) {
        element.textContent = message;
        element.classList.remove('hidden');
    }

    function hideError(element) {
        element.textContent = '';
        element.classList.add('hidden');
    }

    function setLoading(btn, textEl, spinnerEl, loading) {
        btn.disabled = loading;
        if (loading) {
            textEl.classList.add('hidden');
            spinnerEl.classList.remove('hidden');
        } else {
            textEl.classList.remove('hidden');
            spinnerEl.classList.add('hidden');
        }
    }

    // ============================================
    // Password Toggle
    // ============================================
    const togglePasswordBtn = document.getElementById('togglePassword');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const icon = this.querySelector('i');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
                this.setAttribute('aria-label', 'Passwort verbergen');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
                this.setAttribute('aria-label', 'Passwort anzeigen');
            }
        });
    }

    // ============================================
    // Initialize
    // ============================================
    checkSession();

    // Handle Enter key in password fields
    document.getElementById('password').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            loginForm.dispatchEvent(new Event('submit'));
        }
    });

})();