/**
 * Global App Helpers & Component Renderer
 */

// User Session Management
export function getCurrentUser() {
  const user = localStorage.getItem('cyber_user');
  if (user) {
    try {
      return JSON.parse(user);
    } catch (e) {
      return { username: 'Auditor', role: 'auditor' };
    }
  }
  return { username: 'Admin', role: 'admin' };
}

export function setCurrentUser(user) {
  localStorage.setItem('cyber_user', JSON.stringify(user));
}

export function logoutUser() {
  localStorage.removeItem('cyber_user');
  window.location.href = 'login.html';
}

// Format ISO date
export function formatDate(isoString) {
  if (!isoString) return 'N/A';
  const date = new Date(isoString);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Get Badge Class for Vulnerability Severity
export function getSeverityBadgeClass(severity) {
  const sev = (severity || '').toLowerCase();
  switch (sev) {
    case 'critical': return 'bg-critical';
    case 'high': return 'bg-high';
    case 'medium': return 'bg-medium';
    case 'low': return 'bg-low';
    default: return 'bg-safe';
  }
}

// Toast Notifications
export function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'position-fixed bottom-0 end-0 p-3';
    toastContainer.style.zIndex = '9999';
    document.body.appendChild(toastContainer);
  }

  const bgClass = type === 'danger' ? 'bg-danger' : type === 'success' ? 'bg-success' : 'bg-primary';
  const toastId = 'toast-' + Date.now();

  const toastHtml = `
    <div id="${toastId}" class="toast align-items-center text-white ${bgClass} border-0 show" role="alert">
      <div class="d-flex">
        <div class="toast-body">
          <i class="bi ${type === 'success' ? 'bi-check-circle' : type === 'danger' ? 'bi-exclamation-triangle' : 'bi-info-circle'} me-2"></i>
          ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>
  `;

  toastContainer.insertAdjacentHTML('beforeend', toastHtml);
  setTimeout(() => {
    const el = document.getElementById(toastId);
    if (el) el.remove();
  }, 4000);
}

// Render Top Navbar
export function renderNavbar(activePage = 'dashboard') {
  const navContainer = document.getElementById('navbar-mount');
  if (!navContainer) return;

  const user = getCurrentUser();

  navContainer.innerHTML = `
    <nav class="navbar navbar-expand-lg navbar-dark navbar-cyber">
      <div class="container-fluid">
        <a class="navbar-brand d-flex align-items-center" href="index.html">
          <i class="bi bi-shield-lock-fill brand-glow me-2 fs-4"></i>
          CYBER<span class="brand-glow">AUDIT</span>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navContent">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navContent">
          <ul class="navbar-nav me-auto mb-2 mb-lg-0 ms-lg-4">
            <li class="nav-item">
              <a class="nav-link ${activePage === 'dashboard' ? 'active' : ''}" href="index.html">
                <i class="bi bi-grid-1x2-fill me-1"></i> Dashboard
              </a>
            </li>
            <li class="nav-item">
              <a class="nav-link ${activePage === 'inventory' ? 'active' : ''}" href="inventory.html">
                <i class="bi bi-hdd-network-fill me-1"></i> Inventory
              </a>
            </li>
            <li class="nav-item">
              <a class="nav-link ${activePage === 'audits' ? 'active' : ''}" href="audits.html">
                <i class="bi bi-shield-check me-1"></i> Audit History
              </a>
            </li>
            <li class="nav-item">
              <a class="nav-link ${activePage === 'scan' ? 'active' : ''}" href="scan.html">
                <i class="bi bi-radar me-1"></i> Run Scan
              </a>
            </li>
          </ul>
          <div class="d-flex align-items-center gap-3">
            <a href="scan.html" class="btn btn-cyber-primary btn-sm d-none d-md-inline-flex align-items-center gap-1">
              <i class="bi bi-plus-lg"></i> New Audit
            </a>
            <div class="dropdown">
              <button class="btn btn-cyber-outline btn-sm dropdown-toggle d-flex align-items-center gap-2" type="button" data-bs-toggle="dropdown">
                <i class="bi bi-person-circle fs-6"></i>
                <span>${user.username}</span>
                <span class="badge bg-secondary rounded-pill">${user.role}</span>
              </button>
              <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end shadow-lg" style="background:#0f172a; border:1px solid rgba(255,255,255,0.1);">
                <li><a class="dropdown-item text-muted" href="#"><i class="bi bi-gear me-2"></i>Settings</a></li>
                <li><hr class="dropdown-divider border-secondary"></li>
                <li><a class="dropdown-item text-danger" id="logout-btn" href="#"><i class="bi bi-box-arrow-right me-2"></i>Sign Out</a></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </nav>
  `;

  document.getElementById('logout-btn')?.addEventListener('click', (e) => {
    e.preventDefault();
    logoutUser();
  });
}
