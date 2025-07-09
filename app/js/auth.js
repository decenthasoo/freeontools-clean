// Set BACKEND_URL based on environment
const BACKEND_URL =
  window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000'
    : 'https://api.freeontools.com';

// Check if jwt-decode is loaded
if (typeof jwt_decode === 'undefined') {
  console.error('auth.js: jwt-decode library not loaded');
}

// Track pending state to prevent flicker in UI
let isAuthCheckPending = false;

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const socialToken = urlParams.get('token');

  // Store social token from URL
  if (socialToken && window.location.pathname === '/profile.html') {
    localStorage.setItem('token', socialToken);
    localStorage.setItem('sessionAuth', 'true');
    window.history.replaceState({}, document.title, window.location.pathname);
    isAuthCheckPending = true;
  }

  // Handle password reset token validation
  if (window.location.pathname === '/reset-password.html') {
    localStorage.removeItem('token');
    localStorage.removeItem('sessionAuth');
    const resetToken = decodeURIComponent(urlParams.get('token') || '');

    if (resetToken) {
      try {
        const response = await fetch(`${BACKEND_URL}/api/validate-reset-token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: resetToken }),
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

  // Setup form listeners
  setupFormListeners();

  // Setup social buttons
  const socialButtons = document.querySelectorAll('.social-btn');
  socialButtons.forEach(button => {
    button.addEventListener('click', () => {
      const provider = button.classList.contains('google-btn') ? 'google' : 'facebook';
      window.location.href = `${BACKEND_URL}/api/auth/${provider}`;
    });
  });
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
          localStorage.setItem('token', data.token);
          localStorage.setItem('sessionAuth', 'true');
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
          localStorage.setItem('token', data.token);
          localStorage.setItem('sessionAuth', 'true');
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

// Handle logout
document.addEventListener('click', async (e) => {
  if (
    e.target.id === 'logout-btn' ||
    e.target.classList.contains('hamburger-logout-btn') ||
    e.target.closest('a[href="/logout"]')
  ) {
    e.preventDefault();
    localStorage.removeItem('token');
    localStorage.removeItem('sessionAuth');
    try {
      await fetch(`${BACKEND_URL}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {}
    window.updateHeader(false);
    window.location.href = '/';
  }
});
