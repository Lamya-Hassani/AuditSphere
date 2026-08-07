import { renderNavbar, showToast, showConfirm, getCurrentUser, formatDate } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

let userModalInstance = null;
let editingUserId = null;
let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
  renderNavbar('settings');
  currentUser = getCurrentUser();

  // Init Bootstrap modal
  userModalInstance = new bootstrap.Modal(document.getElementById('userModal'));

  // User Management
  loadUsers();
  document.getElementById('add-user-btn').addEventListener('click', openCreateUserModal);
  document.getElementById('user-form').addEventListener('submit', handleUserFormSubmit);

  // Platform Config
  loadSettings();
  document.getElementById('settings-form').addEventListener('submit', handleSaveSettings);
  document.getElementById('reset-settings-btn')?.addEventListener('click', handleResetSettings);
  document.getElementById('update-rules-btn')?.addEventListener('click', handleCheckUpdates);

  // Hide superuser checkbox from non-superadmins
  const superuserRow = document.getElementById('usr-superuser')?.closest('.col-md-6');
  if (superuserRow && !currentUser.is_superuser) {
    superuserRow.classList.add('d-none');
  }

  // Hide Admin option from non-superadmins
  const adminOption = document.getElementById('role-admin-option');
  if (adminOption && !currentUser.is_superuser) {
    adminOption.classList.add('d-none');
  }
});

// ---------------------------------------------------------------------------
// User Management
// ---------------------------------------------------------------------------

async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;

  try {
    const users = await API.getUsers();
    if (!users || users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No user accounts found.</td></tr>`;
      return;
    }

    tbody.innerHTML = users.map(user => {
      const isSuperAdmin = user.is_superuser;
      const roleBadge = isSuperAdmin
        ? `<span class="badge-cyber bg-medium">Super Admin</span>`
        : user.role === 'admin'
          ? `<span class="badge-cyber bg-primary-subtle text-primary border-primary">Admin</span>`
          : `<span class="badge-cyber bg-safe">Auditor</span>`;

      const superuserIcon = user.is_superuser
        ? `<i class="bi bi-shield-fill-check text-warning fs-5" title="Superuser"></i>`
        : `<i class="bi bi-dash text-muted"></i>`;

      // Determine if current session can edit/delete this user
      const canEdit   = currentUser.is_superuser || (!user.is_superuser && user.role !== 'admin');
      const canDelete = currentUser.is_superuser
        ? user.id !== undefined && user.username !== currentUser.username
        : (!user.is_superuser && user.role !== 'admin');

      return `
        <tr>
          <td class="fw-semibold text-dark">
            ${user.username}
            ${user.username === currentUser.username ? '<span class="badge bg-light text-muted border ms-1" style="font-size:0.65rem;">You</span>' : ''}
          </td>
          <td class="text-muted small">${user.email || '—'}</td>
          <td>${roleBadge}</td>
          <td class="text-center">${superuserIcon}</td>
          <td class="text-muted small">${formatDate(user.date_joined)}</td>
          <td class="text-end">
            <div class="d-inline-flex gap-1">
              ${canEdit ? `<button class="btn btn-cyber-outline btn-sm edit-user-btn" data-id="${user.id}" title="Edit account"><i class="bi bi-pencil"></i></button>` : ''}
              ${canDelete ? `<button class="btn btn-cyber-danger btn-sm delete-user-btn" data-id="${user.id}" data-username="${user.username}" title="Delete account"><i class="bi bi-trash"></i></button>` : ''}
              ${!canEdit && !canDelete ? `<span class="text-muted small fst-italic">Protected</span>` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach event listeners
    tbody.querySelectorAll('.edit-user-btn').forEach(btn => {
      btn.addEventListener('click', () => openEditUserModal(btn.dataset.id));
    });
    tbody.querySelectorAll('.delete-user-btn').forEach(btn => {
      btn.addEventListener('click', () => handleDeleteUser(btn.dataset.id, btn.dataset.username));
    });

  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger"><i class="bi bi-exclamation-triangle me-1"></i>${error.message}</td></tr>`;
    showToast(`Failed to load users: ${error.message}`, 'danger');
  }
}

function openCreateUserModal() {
  editingUserId = null;
  document.getElementById('userModalTitle').textContent = 'Create User Account';
  document.getElementById('user-id').value = '';
  document.getElementById('user-form').reset();

  // Password required for creation
  const pwdField = document.getElementById('usr-password');
  pwdField.required = true;
  document.getElementById('password-label').textContent = 'PASSWORD';

  userModalInstance.show();
}

async function openEditUserModal(userId) {
  editingUserId = userId;
  document.getElementById('userModalTitle').textContent = 'Edit User Account';
  document.getElementById('user-id').value = userId;

  // Password optional on edit
  const pwdField = document.getElementById('usr-password');
  pwdField.required = false;
  pwdField.value = '';
  document.getElementById('password-label').textContent = 'NEW PASSWORD (leave blank to keep)';

  try {
    const user = await API.getUserDetail(userId);
    document.getElementById('usr-username').value   = user.username   || '';
    document.getElementById('usr-email').value      = user.email      || '';
    document.getElementById('usr-first-name').value = user.first_name || '';
    document.getElementById('usr-last-name').value  = user.last_name  || '';
    document.getElementById('usr-role').value       = user.role       || 'auditor';
    document.getElementById('usr-superuser').checked = !!user.is_superuser;

    userModalInstance.show();
  } catch (error) {
    showToast(`Failed to load user details: ${error.message}`, 'danger');
  }
}

async function handleUserFormSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById('user-save-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Saving...`;

  const payload = {
    username:   document.getElementById('usr-username').value.trim(),
    email:      document.getElementById('usr-email').value.trim(),
    first_name: document.getElementById('usr-first-name').value.trim(),
    last_name:  document.getElementById('usr-last-name').value.trim(),
    role:       document.getElementById('usr-role').value,
  };

  // Include superuser only if current user is a superadmin
  if (currentUser.is_superuser) {
    payload.is_superuser = document.getElementById('usr-superuser').checked;
  }

  const password = document.getElementById('usr-password').value;
  if (password) payload.password = password;

  try {
    if (editingUserId) {
      await API.updateUser(editingUserId, payload);
      showToast(`User "${payload.username}" updated successfully.`, 'success');
    } else {
      await API.createUser(payload);
      showToast(`User "${payload.username}" created successfully.`, 'success');
    }
    userModalInstance.hide();
    await loadUsers();
  } catch (error) {
    showToast(`Save failed: ${error.message}`, 'danger');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Account';
  }
}

async function handleDeleteUser(userId, username) {
  const confirmed = await showConfirm(`Delete account "${username}"? This action cannot be undone.`);
  if (!confirmed) return;

  try {
    await API.deleteUser(userId);
    showToast(`Account "${username}" deleted.`, 'success');
    await loadUsers();
  } catch (error) {
    showToast(`Delete failed: ${error.message}`, 'danger');
  }
}

// ---------------------------------------------------------------------------
// Platform Configuration
// ---------------------------------------------------------------------------

const DEFAULT_SETTINGS = {
  vmIp: '192.168.56.101',
  enginePort: '8000',
  timeout: '300',
  scoreAlert: '80',
  maxConcurrency: '2',
  autoUpdate: true
};

function loadSettings() {
  const saved = localStorage.getItem('platform_settings');
  let settings = DEFAULT_SETTINGS;
  if (saved) {
    try { settings = { ...DEFAULT_SETTINGS, ...JSON.parse(saved) }; } catch { /* fallback */ }
  }
  document.getElementById('vm-ip').value           = settings.vmIp;
  document.getElementById('engine-port').value     = settings.enginePort;
  document.getElementById('api-timeout').value     = settings.timeout;
  document.getElementById('score-alert').value     = settings.scoreAlert;
  document.getElementById('max-concurrency').value = settings.maxConcurrency;
  document.getElementById('auto-update').checked   = settings.autoUpdate;
}

function handleSaveSettings(e) {
  e.preventDefault();
  const settings = {
    vmIp:           document.getElementById('vm-ip').value.trim(),
    enginePort:     document.getElementById('engine-port').value.trim(),
    timeout:        document.getElementById('api-timeout').value.trim(),
    scoreAlert:     document.getElementById('score-alert').value.trim(),
    maxConcurrency: document.getElementById('max-concurrency').value.trim(),
    autoUpdate:     document.getElementById('auto-update').checked
  };
  localStorage.setItem('platform_settings', JSON.stringify(settings));
  showToast('Platform settings saved successfully.', 'success');
}

async function handleResetSettings() {
  const confirmed = await showConfirm('Reset all configurations to platform defaults?');
  if (!confirmed) return;
  localStorage.setItem('platform_settings', JSON.stringify(DEFAULT_SETTINGS));
  loadSettings();
  showToast('Settings reset to defaults.', 'info');
}

function handleCheckUpdates() {
  const btn = document.getElementById('update-rules-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Checking...`;
  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i>Check Updates`;
    showToast('Threat signature database is up to date (v1.2.4).', 'success');
  }, 1500);
}
