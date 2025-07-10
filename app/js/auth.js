const BACKEND_URL =
  window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000'
    : 'https://api.freeontools.com';

console.log('auth.js: Script loaded');

let cachedAuthStatus = null;
window.authReady = false; // Flag to indicate auth processing is complete

// Handle social login token synchronously on script load
const urlParams = new URLSearchParams(window.location.search);
const socialToken = urlParams.get('token');
if (socialToken && window.location.pathname === '/profile.html') {
    console.log('auth.js: Social login detected, setting token and sessionAuth');
    localStorage.setItem('token', socialToken);
    localStorage.setItem('sessionAuth', 'true');
    window.history.replaceState({}, document.title, window.location.pathname);
    cachedAuthStatus = null; // Reset to force token validation
}

async function checkAuthStatus(attempt = 1, maxAttempts = 3) {
    if (cachedAuthStatus !== null) {
        console.log('auth.js: Returning cached auth status:', cachedAuthStatus);
        return cachedAuthStatus;
    }
    console.log(`auth.js: Checking auth status for ${window.location.pathname}, attempt ${attempt}`);
    if (window.location.pathname === '/reset-password.html') {
        console.log('auth.js: On reset-password.html, bypassing auth check');
        return false;
    }
    const token = localStorage.getItem('token');
    if (!token) {
        console.log('auth.js: No token found, removing sessionAuth');
        localStorage.removeItem('sessionAuth');
        cachedAuthStatus = false;
        return false;
    }
    try {
        const response = await fetch(`${BACKEND_URL}/api/validate-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
        });
        const data = await response.json();
        console.log('auth.js: Token validation response:', data);
        if (data.valid) {
            localStorage.setItem('sessionAuth', 'true');
            cachedAuthStatus = true;
            return true;
        }
        console.log('auth.js: Token invalid, removing sessionAuth and token');
        localStorage.removeItem('sessionAuth');
        localStorage.removeItem('token');
        cachedAuthStatus = false;
        return false;
    } catch (error) {
        console.error(`auth.js: Token validation error on attempt ${attempt}:`, error);
        if (attempt < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 100));
            return checkAuthStatus(attempt + 1, maxAttempts);
        }
        console.log('auth.js: Max auth check attempts reached');
        localStorage.removeItem('sessionAuth');
        localStorage.removeItem('token');
        cachedAuthStatus = false;
        return false;
    }
}
window.checkAuthStatus = checkAuthStatus;

async function updateHeader(attempt = 1, maxAttempts = 5) {
    console.log(`auth.js: updateHeader called for ${window.location.pathname}, attempt ${attempt}`);
    const headerButtons = document.querySelector('.header-buttons');
    const hamburgerContent = document.querySelector('.hamburger-content');
    const navDropdownContent = document.querySelector('.nav-has-dropdown .dropdown-content .tool-list');
    if (!headerButtons || !hamburgerContent || !navDropdownContent) {
        if (attempt < maxAttempts) {
            console.warn(`auth.js: Header elements not found on attempt ${attempt}, retrying...`);
            await new Promise(resolve => setTimeout(resolve, 50));
            return updateHeader(attempt + 1, maxAttempts);
        }
        console.warn(`auth.js: Header elements not found after ${maxAttempts} attempts`);
        return;
    }
    const isAuthenticated = await checkAuthStatus();
    if (isAuthenticated) {
        console.log('auth.js: Authenticated, setting Profile and Logout');
        headerButtons.innerHTML = `
            <a href="/profile.html" class="header-btn signup-btn">Profile</a>
            <a href="/logout" class="header-btn login-btn" id="logout-btn">Logout</a>
        `;
        const signupBtn = hamburgerContent.querySelector('.hamburger-signup-btn');
        const loginBtn = hamburgerContent.querySelector('.hamburger-login-btn');
        if (signupBtn) signupBtn.style.display = 'none';
        if (loginBtn) loginBtn.style.display = 'none';
        if (!hamburgerContent.querySelector('.hamburger-profile-btn')) {
            hamburgerContent.insertAdjacentHTML('beforeend', `
                <a href="/profile.html" class="header-btn hamburger-signup-btn hamburger-profile-btn">Profile</a>
                <a href="/logout" class="header-btn hamburger-login-btn hamburger-logout-btn" id="hamburger-logout-btn">Logout</a>
            `);
        }
        const profileLink = navDropdownContent.querySelector('a[href="/profile"]');
        const settingsLink = navDropdownContent.querySelector('a[href="/settings"]');
        const logoutLink = navDropdownContent.querySelector('a[href="/logout"]');
        if (profileLink) profileLink.style.display = 'block';
        if (settingsLink) settingsLink.style.display = 'block';
        if (logoutLink) logoutLink.style.display = 'block';
    } else {
        console.log('auth.js: Not authenticated, setting Sign Up and Login');
        headerButtons.innerHTML = `
            <a href="/signup.html" class="header-btn signup-btn">Sign Up</a>
            <a href="/login.html" class="header-btn login-btn">Login</a>
        `;
        const signupBtn = hamburgerContent.querySelector('.hamburger-signup-btn');
        const loginBtn = hamburgerContent.querySelector('.hamburger-login-btn');
        const profileBtn = hamburgerContent.querySelector('.hamburger-profile-btn');
        const logoutBtn = hamburgerContent.querySelector('.hamburger-logout-btn');
        if (signupBtn) signupBtn.style.display = 'block';
        if (loginBtn) loginBtn.style.display = 'block';
        if (profileBtn) profileBtn.remove();
        if (logoutBtn) logoutBtn.remove();
        const profileLink = navDropdownContent.querySelector('a[href="/profile"]');
        const settingsLink = navDropdownContent.querySelector('a[href="/settings"]');
        const logoutLink = navDropdownContent.querySelector('a[href="/logout"]');
        if (profileLink) profileLink.style.display = 'none';
        if (settingsLink) settingsLink.style.display = 'none';
        if (logoutLink) logoutLink.style.display = 'none';
    }
}
window.updateHeader = updateHeader;

// Run initial auth check and header update for social login
if (socialToken && window.location.pathname === '/profile.html') {
    console.log('auth.js: Running initial auth check for social login');
    checkAuthStatus().then(() => {
        updateHeader();
        window.authReady = true; // Signal auth processing is complete
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('auth.js: DOMContentLoaded fired');

    if (window.location.pathname === '/reset-password.html') {
        console.log('auth.js: On reset-password.html, clearing auth data');
        localStorage.removeItem('token');
        localStorage.removeItem('sessionAuth');
        cachedAuthStatus = null;
        const token = decodeURIComponent(urlParams.get('token') || '');
        if (token) {
            try {
                const response = await fetch(`${BACKEND_URL}/api/validate-reset-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token }),
                });
                const data = await response.json();
                if (!data.valid) {
                    document.getElementById('error-message').textContent = data.message;
                    setTimeout(() => (window.location.href = '/login.html'), 2000);
                    return;
                }
            } catch (error) {
                document.getElementById('error-message').textContent = 'Error validating token';
                setTimeout(() => (window.location.href = '/login.html'), 2000);
                return;
            }
        } else {
            document.getElementById('error-message').textContent = 'No reset token provided';
            setTimeout(() => (window.location.href = '/login.html'), 2000);
            return;
        }
    }

    setupFormListeners();

    const socialButtons = document.querySelectorAll('.social-btn');
    socialButtons.forEach(button => {
        button.addEventListener('click', () => {
            const provider = button.classList.contains('google-btn') ? 'google' : 'facebook';
            window.location.href = `${BACKEND_URL}/api/auth/${provider}`;
        });
    });

    if (!(socialToken && window.location.pathname === '/profile.html')) {
        await updateHeader();
    }

    window.authReady = true; // Signal auth processing is complete for non-social login
});

function setupFormListeners() {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const resetPasswordForm = document.getElementById('reset-password-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch(`${BACKEND_URL}/api/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });
                const data = await response.json();
                if (response.ok) {
                    console.log('auth.js: Login successful, setting token and sessionAuth');
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('sessionAuth', 'true');
                    cachedAuthStatus = true;
                    await updateHeader();
                    window.location.href = '/profile.html';
                } else {
                    errorMessage.textContent = data.message || 'Login failed';
                }
            } catch {
                errorMessage.textContent = 'An error occurred. Please try again.';
            }
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch(`${BACKEND_URL}/api/signup`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password }),
                });
                const data = await response.json();
                if (response.ok) {
                    console.log('auth.js: Signup successful, setting token and sessionAuth');
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('sessionAuth', 'true');
                    cachedAuthStatus = true;
                    await updateHeader();
                    window.location.href = '/profile.html';
                } else {
                    errorMessage.textContent = data.message || 'Signup failed';
                }
            } catch {
                errorMessage.textContent = 'An error occurred. Please try again.';
            }
        });
    }

    if (forgotPasswordForm) {
        const submitBtn = forgotPasswordForm.querySelector('button[type="submit"]');
        const loadingSpan = document.getElementById('loading-indicator');
        forgotPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            if (submitBtn && loadingSpan) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Sending...';
                loadingSpan.style.display = 'inline';
            }

            try {
                const response = await fetch(`${BACKEND_URL}/api/forgot-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email }),
                });
                const data = await response.json();
                if (response.ok) {
                    successMessage.textContent = data.message;
                    errorMessage.textContent = '';
                } else {
                    errorMessage.textContent = data.message || 'Failed to send reset link';
                    successMessage.textContent = '';
                }
            } catch {
                errorMessage.textContent = 'An error occurred. Please try again.';
                successMessage.textContent = '';
            } finally {
                if (submitBtn && loadingSpan) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Send Reset Link';
                    loadingSpan.style.display = 'none';
                }
            }
        });
    }

    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const token = decodeURIComponent(new URLSearchParams(window.location.search).get('token') || '');

            if (!token) {
                errorMessage.textContent = 'No reset token provided.';
                return;
            }

            if (password !== confirmPassword) {
                errorMessage.textContent = 'Passwords do not match';
                return;
            }

            if (password.length < 8) {
                errorMessage.textContent = 'Password must be at least 8 characters';
                return;
            }

            try {
                const validateResponse = await fetch(`${BACKEND_URL}/api/validate-reset-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token }),
                });
                const validateData = await validateResponse.json();
                if (!validateData.valid) {
                    errorMessage.textContent = validateData.message || 'Invalid token';
                    setTimeout(() => (window.location.href = '/login.html'), 2000);
                    return;
                }
            } catch {
                errorMessage.textContent = 'Error validating token';
                return;
            }

            try {
                const response = await fetch(`${BACKEND_URL}/api/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, password }),
                });
                const data = await response.json();
                if (response.ok) {
                    successMessage.textContent = data.message;
                    errorMessage.textContent = '';
                    setTimeout(() => (window.location.href = '/login.html'), 2000);
                } else {
                    errorMessage.textContent = data.message || 'Failed to reset password';
                }
            } catch {
                errorMessage.textContent = 'An error occurred. Please try again.';
            }
        });
    }
}

document.addEventListener('click', async (e) => {
    if (
        e.target.id === 'logout-btn' ||
        e.target.id === 'hamburger-logout-btn' ||
        e.target.closest('a[href="/logout"]')
    ) {
        e.preventDefault();
        localStorage.removeItem('token');
        localStorage.removeItem('sessionAuth');
        cachedAuthStatus = false;
        try {
            await fetch(`${BACKEND_URL}/logout`, {
                method: 'POST',
                credentials: 'include',
            });
        } catch {}
        await window.updateHeader();
        window.location.href = '/';
    }
});