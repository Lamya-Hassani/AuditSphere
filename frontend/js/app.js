/**
 * AuditSphere - Global App Helpers & Component Renderer
 */
import { getAccessToken, clearTokens } from './api.js?v=1.0.3';

// ---------------------------------------------------------------------------
// Auth Guard
// ---------------------------------------------------------------------------
export function requireAuth() {
  const isLoginPage = window.location.pathname.endsWith('login.html');
  const token = getAccessToken();

  if (!token && !isLoginPage) {
    window.location.href = 'login.html';
    return false;
  }
  if (token && isLoginPage) {
    window.location.href = 'index.html';
    return false;
  }
  return true;
}

requireAuth();

// ---------------------------------------------------------------------------
// User Session
// ---------------------------------------------------------------------------
export function getCurrentUser() {
  const raw = localStorage.getItem('cyber_user') || sessionStorage.getItem('cyber_user');
  if (raw) {
    try { return JSON.parse(raw); } catch { /* fall through */ }
  }
  return { username: 'Admin', role: 'admin', is_superuser: false };
}

export function setCurrentUser(user) {
  const storage = localStorage.getItem('access_token') ? localStorage : sessionStorage;
  storage.setItem('cyber_user', JSON.stringify(user));
}

export async function logoutUser() {
  try {
    const refresh = localStorage.getItem('refresh_token') || sessionStorage.getItem('refresh_token');
    if (refresh) {
      await fetch('http://localhost:8000/api/accounts/logout/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh })
      });
    }
  } catch { /* ignore network errors on logout */ }
  clearTokens();
  navigateTo('login.html');
}

// ---------------------------------------------------------------------------
// Navigation with smooth fade transition
// ---------------------------------------------------------------------------
export function navigateTo(url) {
  document.body.classList.add('page-exit');
  setTimeout(() => { window.location.href = url; }, 180);
}

// Intercept all nav-item-link clicks for smooth transition
function attachNavTransitions() {
  document.querySelectorAll('a.nav-item-link, a[data-nav]').forEach(link => {
    link.addEventListener('click', e => {
      const href = link.getAttribute('href');
      if (href && !href.startsWith('#') && !href.startsWith('http')) {
        e.preventDefault();
        navigateTo(href);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
export function formatDate(isoString) {
  if (!isoString) return 'N/A';
  return new Date(isoString).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

export function getSeverityBadgeClass(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'bg-critical';
    case 'high':     return 'bg-high';
    case 'medium':   return 'bg-medium';
    case 'low':      return 'bg-low';
    default:         return 'bg-safe';
  }
}

// ---------------------------------------------------------------------------
// Toast Notifications
// ---------------------------------------------------------------------------
export function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'position-fixed bottom-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
  }

  const iconMap   = { success: 'bi-check-circle-fill', danger: 'bi-exclamation-triangle-fill', warning: 'bi-exclamation-circle-fill', info: 'bi-info-circle-fill' };
  const colorMap  = { success: '#10b981', danger: '#ef4444', warning: '#f59e0b', info: '#2563eb' };
  const id        = `toast-${Date.now()}`;
  const color     = colorMap[type] || colorMap.info;
  const icon      = iconMap[type]  || iconMap.info;

  container.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast-item" role="alert" style="border-left: 4px solid ${color};">
      <i class="bi ${icon} me-2" style="color:${color};"></i>
      <span class="flex-grow-1">${message}</span>
      <button class="toast-close" onclick="this.closest('.toast-item').remove()">&times;</button>
    </div>
  `);

  setTimeout(() => document.getElementById(id)?.remove(), 5000);
}

// Confirmation dialog (returns Promise<boolean>)
export function showConfirm(message) {
  return new Promise(resolve => {
    const id = `confirm-${Date.now()}`;
    document.body.insertAdjacentHTML('beforeend', `
      <div class="confirm-overlay" id="${id}">
        <div class="confirm-box">
          <p class="confirm-msg">${message}</p>
          <div class="confirm-actions">
            <button class="btn btn-cyber-outline" id="${id}-cancel">Cancel</button>
            <button class="btn btn-cyber-danger" id="${id}-ok">Confirm</button>
          </div>
        </div>
      </div>
    `);
    document.getElementById(`${id}-cancel`).onclick = () => { document.getElementById(id)?.remove(); resolve(false); };
    document.getElementById(`${id}-ok`).onclick    = () => { document.getElementById(id)?.remove(); resolve(true);  };
  });
}

// ---------------------------------------------------------------------------
// Sidebar & Topbar Renderer
// ---------------------------------------------------------------------------
export function renderNavbar(activePage = 'dashboard') {
  const navContainer = document.getElementById('navbar-mount');
  if (!navContainer) return;

  const user = getCurrentUser();
  const isSuperAdmin = user.is_superuser === true;
  const isAdmin      = user.role === 'admin' || isSuperAdmin;

  // Show user management link to admins/superadmins
  const usersLink = isAdmin ? `
    <a href="settings.html" class="nav-item-link ${activePage === 'settings' ? 'active' : ''}">
      <i class="bi bi-people-fill"></i><span>User Management</span>
    </a>` : '';

  // Super-admin badge
  const roleBadge = isSuperAdmin
    ? `<span class="user-role d-block text-uppercase" style="color:#f59e0b;">Super Admin</span>`
    : `<span class="user-role d-block text-uppercase">${user.role || 'Auditor'}</span>`;

  navContainer.innerHTML = `
    <!-- Left Sidebar -->
    <aside class="sidebar" id="sidebar-menu">
      <div class="brand">
        <i class="bi bi-shield-lock-fill me-2"></i>AuditSphere
      </div>
      <nav class="nav-links">
        <a href="index.html" class="nav-item-link ${activePage === 'dashboard' ? 'active' : ''}">
          <i class="bi bi-grid-fill"></i><span>Dashboard</span>
        </a>
        <a href="scan.html" class="nav-item-link ${activePage === 'scan' ? 'active' : ''}">
          <i class="bi bi-play-circle-fill"></i><span>Run Audit</span>
        </a>
        <a href="audits.html" class="nav-item-link ${activePage === 'audits' ? 'active' : ''}">
          <i class="bi bi-shield-check"></i><span>Audit History</span>
        </a>
        <a href="inventory.html" class="nav-item-link ${activePage === 'inventory' ? 'active' : ''}">
          <i class="bi bi-hdd-network-fill"></i><span>Inventory</span>
        </a>
        ${usersLink}
      </nav>

      <!-- Sidebar Footer -->
      <div class="sidebar-footer">
        <span>AuditSphere v1.0</span>
        <span>Blueprint · EMSI 2026</span>
      </div>
    </aside>

    <!-- Top Navbar -->
    <header class="top-navbar">
      <div class="d-flex align-items-center">
        <button class="sidebar-toggle" id="sidebar-toggle-btn">
          <i class="bi bi-list"></i>
        </button>
      </div>
      <div class="user-info">
        <div class="user-details d-none d-sm-block">
          <span class="user-name d-block">${user.username || 'Administrator'}</span>
          ${roleBadge}
        </div>
        <button class="btn btn-cyber-outline btn-sm" id="logout-btn">
          <i class="bi bi-box-arrow-right me-1"></i>Logout
        </button>
      </div>
    </header>
  `;

  // Page fade-in on load
  document.body.classList.add('page-enter');

  const toggleBtn = document.getElementById('sidebar-toggle-btn');
  const sidebar = document.getElementById('sidebar-menu');

  if (toggleBtn && sidebar) {
    const isMobile = () => window.innerWidth <= 991.98;

    toggleBtn.addEventListener('click', e => {
      e.stopPropagation();

      if (isMobile()) {
        sidebar.classList.toggle('show');
      } else {
        sidebar.classList.toggle('collapsed');
      }
    });

    document.addEventListener('click', e => {
      if (
        isMobile() &&
        sidebar.classList.contains('show') &&
        !sidebar.contains(e.target) &&
        e.target !== toggleBtn
      ) {
        sidebar.classList.remove('show');
      }
    });

    window.addEventListener('resize', () => {
      if (!isMobile()) {
        sidebar.classList.remove('show');
      }
    });
  }

  // Logout
  document.getElementById('logout-btn')?.addEventListener('click', e => {
    e.preventDefault();
    logoutUser();
  });

  // Smooth nav transitions
  attachNavTransitions();
}
