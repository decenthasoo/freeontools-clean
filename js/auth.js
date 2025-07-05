// Set BACKEND_URL based on environment
const BACKEND_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:3000'
  : 'https://www.freeontools.com';

document.addEventListener('DOMContentLoaded', async () => {
    console.log('auth.js: DOMContentLoaded, initializing auth listeners for', window.location.pathname);
    console.log('auth.js: Using BACKEND_URL:', BACKEND_URL);

    // Handle social login token
    const urlParams = new URLSearchParams(window.location.search);
    const socialToken = urlParams.get('token');
    if (socialToken && window.location.pathname === '/profile.html') {
        console.log('auth.js: Storing token from social login');
        localStorage.setItem('token', socialToken);
        localStorage.setItem('sessionAuth', 'true');
        window.history.replaceState({}, document.title, window.location.pathname);
        await window.updateHeader();
    }

    // Handle reset-password.html
    if (window.location.pathname === '/reset-password.html') {
        console.log('auth.js: On reset-password.html, clearing auth tokens');
        localStorage.removeItem('token');
        localStorage.removeItem('sessionAuth');
        console.log('auth.js: Current URL:', window.location.href);
        console.log('auth.js: URL query string:', window.location.search);
        const resetToken = decodeURIComponent(urlParams.get('token') || '');
        console.log('auth.js: Reset token from URL:', resetToken);
        if (resetToken) {
            try {
                const response = await fetch(`${BACKEND_URL}/api/validate-reset-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: resetToken }),
                });
                const data = await response.json();
                console.log('auth.js: Validate reset token response:', data);
                if (!data.valid) {
                    console.log('auth.js: Invalid or expired reset token, redirecting to login');
                    document.getElementById('error-message').textContent = data.message;
                    setTimeout(() => window.location.href = '/login.html', 2000);
                    return;
                }
                console.log('auth.js: Valid reset token, rendering form');
            } catch (error) {
                console.error('auth.js: Error validating reset token:', error);
                document.getElementById('error-message').textContent = 'Error validating token';
                setTimeout(() => window.location.href = '/login.html', 2000);
                return;
            }
        } else {
            console.log('auth.js: No reset token in URL, redirecting to login');
            document.getElementById('error-message').textContent = 'No reset token provided';
            setTimeout(() => window.location.href = '/login.html', 2000);
            return;
        }
    }

    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const resetPasswordForm = document.getElementById('reset-password-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');

    if (loginForm) {
        console.log('auth.js: Login form found, attaching submit listener');
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            console.log('auth.js: Login form submitted for email:', email);
            try {
                const response = await fetch(`${BACKEND_URL}/api/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });
                console.log('auth.js: Login response status:', response.status);
                const data = await response.json();
                console.log('auth.js: Login response data:', data);
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('sessionAuth', 'true');
                    console.log('auth.js: Login successful, redirecting to profile');
                    window.location.href = '/profile.html';
                } else {
                    errorMessage.textContent = data.message || 'Login failed';
                    console.error('auth.js: Login error:', data.message);
                }
            } catch (error) {
                errorMessage.textContent = 'An error occurred. Please try again.';
                console.error('auth.js: Login fetch error:', error);
            }
        });
    }

    if (signupForm) {
        console.log('auth.js: Signup form found, attaching submit listener');
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            console.log('auth.js: Signup form submitted for email:', email);
            try {
                const response = await fetch(`${BACKEND_URL}/api/signup`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password }),
                });
                console.log('auth.js: Signup response status:', response.status);
                const data = await response.json();
                console.log('auth.js: Signup response data:', data);
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('sessionAuth', 'true');
                    console.log('auth.js: Signup successful, redirecting to profile');
                    window.location.href = '/profile.html';
                } else {
                    errorMessage.textContent = data.message || 'Signup failed';
                    console.error('auth.js: Signup error:', data.message);
                }
            } catch (error) {
                errorMessage.textContent = 'An error occurred. Please try again.';
                console.error('auth.js: Signup fetch error:', error);
            }
        });
    }

    if (forgotPasswordForm) {
        console.log('auth.js: Forgot password form found, attaching submit listener');
        const submitButton = forgotPasswordForm.querySelector('button[type="submit"]');
        const loadingSpan = document.getElementById('loading-indicator');
        forgotPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (submitButton && loadingSpan) {
                submitButton.disabled = true;
                submitButton.textContent = 'Sending...';
                loadingSpan.style.display = 'inline';
            }
            const email = document.getElementById('email').value;
            console.log('auth.js: Forgot password submitted for email:', email);
            try {
                const response = await fetch(`${BACKEND_URL}/api/forgot-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email }),
                });
                const data = await response.json();
                console.log('auth.js: Forgot password response:', data);
                if (response.ok) {
                    successMessage.textContent = data.message;
                    errorMessage.textContent = '';
                } else {
                    errorMessage.textContent = data.message || 'Failed to send reset link';
                    successMessage.textContent = '';
                }
            } catch (error) {
                errorMessage.textContent = 'An error occurred. Please try again.';
                successMessage.textContent = '';
                console.error('auth.js: Forgot password error:', error);
            } finally {
                if (submitButton && loadingSpan) {
                    submitButton.disabled = false;
                    submitButton.textContent = 'Send Reset Link';
                    loadingSpan.style.display = 'none';
                }
            }
        });
    }

    if (resetPasswordForm) {
        console.log('auth.js: Reset password form found, attaching submit listener');
        resetPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            console.log('auth.js: Current URL:', window.location.href);
            console.log('auth.js: URL query string:', window.location.search);
            const resetToken = decodeURIComponent(new URLSearchParams(window.location.search).get('token') || '');
            console.log('auth.js: Reset password submitted with token:', resetToken);
            if (!resetToken) {
                console.log('auth.js: Reset password failed: No token provided in URL');
                errorMessage.textContent = 'No reset token provided. Please use the link from your email.';
                successMessage.textContent = '';
                return;
            }
            try {
                const validateResponse = await fetch(`${BACKEND_URL}/api/validate-reset-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: resetToken }),
                });
                const validateData = await validateResponse.json();
                console.log('auth.js: Pre-submission token validation response:', validateData);
                if (!validateData.valid) {
                    console.log('auth.js: Reset password failed: Invalid or expired token');
                    errorMessage.textContent = validateData.message || 'Invalid or expired token';
                    successMessage.textContent = '';
                    setTimeout(() => window.location.href = '/login.html', 2000);
                    return;
                }
            } catch (error) {
                console.error('auth.js: Error revalidating reset token:', error);
                errorMessage.textContent = 'Error validating token. Please try again.';
                successMessage.textContent = '';
                setTimeout(() => window.location.href = '/login.html', 2000);
                return;
            }
            if (password !== confirmPassword) {
                console.log('auth.js: Reset password failed: Passwords do not match');
                errorMessage.textContent = 'Passwords do not match';
                successMessage.textContent = '';
                return;
            }
            if (password.length < 8) {
                console.log('auth.js: Reset password failed: Password too short');
                errorMessage.textContent = 'Password must be at least 8 characters long';
                successMessage.textContent = '';
                return;
            }
            try {
                const response = await fetch(`${BACKEND_URL}/api/reset-password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: resetToken, password }),
                });
                const data = await response.json();
                console.log('auth.js: Reset password response:', data);
                if (response.ok) {
                    console.log('auth.js: Password reset successful, redirecting to login');
                    successMessage.textContent = data.message;
                    errorMessage.textContent = '';
                    setTimeout(() => {
                        window.location.href = '/login.html';
                    }, 2000);
                } else {
                    console.log('auth.js: Reset password error:', data.message);
                    errorMessage.textContent = data.message || 'Failed to reset password';
                    successMessage.textContent = '';
                }
            } catch (error) {
                console.error('auth.js: Reset password fetch error:', error);
                errorMessage.textContent = 'An error occurred. Please try again.';
                successMessage.textContent = '';
            }
        });
    }

    const socialButtons = document.querySelectorAll('.social-btn');
    if (socialButtons.length > 0) {
        console.log('auth.js: Social login buttons found:', socialButtons.length);
        socialButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const provider = button.classList.contains('google-btn') ? 'Google' : 'Facebook';
                console.log(`auth.js: Social login clicked for ${provider}`);
                if (provider === 'Google') {
                    window.location.href = `${BACKEND_URL}/api/auth/google`;
                    console.log('auth.js: Redirecting to Google auth');
                } else if (provider === 'Facebook') {
                    window.location.href = `${BACKEND_URL}/api/auth/facebook`;
                    console.log('auth.js: Redirecting to Facebook auth');
                }
            });
        });
    }

    await window.updateHeader();
});

// Explicitly define updateHeader as a global function
window.updateHeader = async function(attempt = 1, maxAttempts = 10) {
    console.log(`auth.js: updateHeader attempt ${attempt} for ${window.location.pathname}`);
    const token = localStorage.getItem('token');
    const headerButtons = document.querySelector('.header-buttons');
    const hamburgerContent = document.querySelector('.hamburger-content');
    const navDropdownContent = document.querySelector('.nav-has-dropdown .dropdown-content .tool-list');
    console.log('auth.js: Token:', token ? token.slice(0, 20) + '...' : null);
    console.log('auth.js: Header Buttons found:', !!headerButtons);
    console.log('auth.js: Hamburger Content found:', !!hamburgerContent);
    console.log('auth.js: Nav Dropdown Content found:', !!navDropdownContent);
    if (attempt > maxAttempts) {
        console.error(`auth.js: Failed to update header after ${maxAttempts} attempts`);
        return;
    }
    if (!headerButtons || !hamburgerContent || !navDropdownContent) {
        console.log(`auth.js: Header elements not found, retrying in 100ms (attempt ${attempt})`);
        setTimeout(() => window.updateHeader(attempt + 1, maxAttempts), 100);
        return;
    }
    const isAuthenticated = await checkAuthStatus();
    if (isAuthenticated) {
        console.log('auth.js: Auth present, setting Profile and Logout');
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
                <a href="/logout" class="header-btn hamburger-login-btn hamburger-logout-btn">Logout</a>
            `);
        }
        const profileLink = navDropdownContent.querySelector('a[href="/profile.html"]');
        const settingsLink = navDropdownContent.querySelector('a[href="/settings.html"]');
        const logoutLink = navDropdownContent.querySelector('a[href="/logout"]');
        if (profileLink) {
            profileLink.style.display = 'block';
            profileLink.classList.add('header-btn', 'signup-btn');
        }
        if (settingsLink) {
            settingsLink.style.display = 'block';
            settingsLink.classList.add('header-btn', 'signup-btn');
        }
        if (logoutLink) {
            logoutLink.style.display = 'block';
            logoutLink.classList.add('header-btn', 'login-btn');
        }
    } else {
        console.log('auth.js: No auth, setting Sign Up and Login');
        headerButtons.innerHTML = `
            <a href="/signup.html" class="header-btn signup-btn">Sign Up</a>
            <a href="/login.html" class="header-btn login-btn">Login</a>
        `;
        const signupBtn = hamburgerContent.querySelector('.hamburger-signup-btn');
        const loginBtn = hamburgerContent.querySelector('.hamburger-login-btn');
        if (signupBtn) signupBtn.style.display = 'block';
        if (loginBtn) loginBtn.style.display = 'block';
        const profileBtn = hamburgerContent.querySelector('.hamburger-profile-btn');
        const logoutBtn = hamburgerContent.querySelector('.hamburger-logout-btn');
        if (profileBtn) profileBtn.remove();
        if (logoutBtn) logoutBtn.remove();
        const profileLink = navDropdownContent.querySelector('a[href="/profile.html"]');
        const settingsLink = navDropdownContent.querySelector('a[href="/settings.html"]');
        const logoutLink = navDropdownContent.querySelector('a[href="/logout"]');
        if (profileLink) {
            profileLink.style.display = 'none';
            profileLink.classList.remove('header-btn', 'signup-btn');
        }
        if (settingsLink) {
            settingsLink.style.display = 'none';
            settingsLink.classList.remove('header-btn', 'signup-btn');
        }
        if (logoutLink) {
            logoutLink.style.display = 'none';
            logoutLink.classList.remove('header-btn', 'login-btn');
        }
    }
};

async function checkAuthStatus(attempt = 1, maxAttempts = 10) {
    console.log(`auth.js: Checking auth status for ${window.location.pathname}, attempt ${attempt}`);
    if (window.location.pathname === '/reset-password.html') {
        console.log('auth.js: On reset-password.html, bypassing auth check');
        return false;
    }
    const token = localStorage.getItem('token');
    if (token) {
        console.log('auth.js: Token found, assuming authenticated');
        localStorage.setItem('sessionAuth', 'true');
        return true;
    }
    try {
        const response = await fetch(`${BACKEND_URL}/auth/check`, {
            method: 'GET',
            credentials: 'include',
            headers: { 'Accept': 'application/json' },
            cache: 'no-store',
        });
        console.log(`auth.js: /auth/check response status: ${response.status}`);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        console.log('auth.js: Auth check response data:', data);
        if (data.authenticated) {
            localStorage.setItem('sessionAuth', 'true');
            console.log('auth.js: Session auth set to true');
            return true;
        }
        localStorage.removeItem('sessionAuth');
        console.log('auth.js: Session auth removed, response:', data);
        return false;
    } catch (error) {
        console.error(`auth.js: Auth check error on attempt ${attempt}:`, error.message);
        localStorage.removeItem('sessionAuth');
        if (attempt < maxAttempts) {
            console.log(`auth.js: Retrying auth check, attempt ${attempt + 1}`);
            await new Promise(resolve => setTimeout(resolve, 300));
            return checkAuthStatus(attempt + 1, maxAttempts);
        }
        console.error('auth.js: Max auth check attempts reached');
        return false;
    }
}

document.addEventListener('click', async (e) => {
    if (e.target.id === 'logout-btn' || e.target.classList.contains('hamburger-logout-btn') || e.target.closest('a[href="/logout"]')) {
        e.preventDefault();
        console.log('auth.js: Logout triggered');
        localStorage.removeItem('token');
        localStorage.removeItem('sessionAuth');
        try {
            const response = await fetch(`${BACKEND_URL}/logout`, {
                method: 'POST',
                credentials: 'include',
            });
            if (response.ok) {
                console.log('auth.js: Server-side logout successful');
            } else {
                console.error('auth.js: Server-side logout failed:', response.status);
            }
        } catch (error) {
            console.error('auth.js: Logout error:', error);
        }
        window.updateHeader();
        window.location.href = '/';
    }
});

console.log('auth.js: Loaded and window.updateHeader defined');