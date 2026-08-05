import { setCurrentUser, showToast } from './app.js';
import { API } from './api.js';

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const demoAdminBtn = document.getElementById('demo-admin');
  const demoAuditorBtn = document.getElementById('demo-auditor');
  const submitBtn = loginForm.querySelector('button[type="submit"]');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!username || !password) {
      showToast('Please enter both username and password', 'danger');
      return;
    }

    const originalBtnHtml = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Authenticating...`;

    try {
      const response = await API.login(username, password);
      const user = response.user;

      setCurrentUser(user);
      showToast(`Welcome back, ${user.username}! Role: ${user.role}`, 'success');

      setTimeout(() => {
        window.location.href = 'index.html';
      }, 600);

    } catch (error) {
      showToast(`Authentication failed: ${error.message}`, 'danger');
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnHtml;
    }
  });

  demoAdminBtn?.addEventListener('click', () => {
    document.getElementById('username').value = 'admin';
    document.getElementById('password').value = 'admin123';
    loginForm.dispatchEvent(new Event('submit'));
  });

  demoAuditorBtn?.addEventListener('click', () => {
    document.getElementById('username').value = 'auditor';
    document.getElementById('password').value = 'auditor123';
    loginForm.dispatchEvent(new Event('submit'));
  });
});
