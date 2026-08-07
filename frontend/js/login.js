import { API } from './api.js?v=1.0.3';
import { setCurrentUser, showToast } from './app.js?v=1.0.3';

function saveTokens(access, refresh, rememberMe = true) {
  const storage = rememberMe ? localStorage : sessionStorage;
  storage.setItem('access_token', access);
  if (refresh) {
    storage.setItem('refresh_token', refresh);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const errorAlert = document.getElementById('error-alert');
  const errorMessage = document.getElementById('error-message');
  const submitBtn = document.getElementById('submit-btn');
  const demoAdminBtn = document.getElementById('demo-admin');
  const demoAuditorBtn = document.getElementById('demo-auditor');

  function showError(msg) {
    if (errorMessage && errorAlert) {
      errorMessage.textContent = msg;
      errorAlert.classList.remove('d-none');
    } else {
      showToast(msg, 'danger');
    }
  }

  function hideError() {
    if (errorAlert) {
      errorAlert.classList.add('d-none');
    }
  }

  loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const rememberMeInput = document.getElementById('remember-me');

    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value.trim() : '';
    const rememberMe = rememberMeInput ? rememberMeInput.checked : true;

    if (!username || !password) {
      showError('Please provide both username/email and password.');
      return;
    }

    const originalBtnHtml = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Authenticating...`;

    try {
      const response = await API.login(username, password);
      
      const access = response.access;
      const refresh = response.refresh;
      const user = response.user;

      if (!access || !user) {
        throw new Error('Invalid authentication response from server.');
      }

      // Store JWT Tokens & Current User Info securely
      saveTokens(access, refresh, rememberMe);
      setCurrentUser(user);

      showToast(`Authentication successful! Welcome, ${user.username}.`, 'success');

      setTimeout(() => {
        window.location.href = 'index.html';
      }, 500);

    } catch (error) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnHtml;

      const detail = error.data?.detail || error.data?.error || error.message;
      if (error.status === 401) {
        showError('401 Unauthorized: Invalid username or password.');
      } else if (error.status === 400) {
        showError('400 Bad Request: Please verify input fields.');
      } else {
        showError(`Authentication Error: ${detail}`);
      }
    }
  });

  demoAdminBtn?.addEventListener('click', () => {
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    if (u) u.value = 'admin';
    if (p) p.value = 'admin123';
    loginForm.dispatchEvent(new Event('submit'));
  });

  demoAuditorBtn?.addEventListener('click', () => {
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    if (u) u.value = 'auditor';
    if (p) p.value = 'auditor123';
    loginForm.dispatchEvent(new Event('submit'));
  });

  // Super Admin demo
  document.getElementById('demo-super')?.addEventListener('click', () => {
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    if (u) u.value = 'super';
    if (p) p.value = 'admin123';
    loginForm.dispatchEvent(new Event('submit'));
  });
});
