import { renderNavbar, showToast, showConfirm, getSeverityBadgeClass, formatDate } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

let currentStatusFilter = '';
let searchDebounce = null;
let deviceModalInstance = null;

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('inventory');

  deviceModalInstance = new bootstrap.Modal(document.getElementById('deviceModal'));

  // Setup Filters
  const btnAll = document.getElementById('filter-all');
  const btnUp = document.getElementById('filter-up');
  const btnDown = document.getElementById('filter-down');

  btnAll.addEventListener('click', () => setFilter('', btnAll));
  btnUp.addEventListener('click', () => setFilter('up', btnUp));
  btnDown.addEventListener('click', () => setFilter('down', btnDown));

  // Search input
  const searchInput = document.getElementById('inventory-search');
  searchInput.addEventListener('input', (e) => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      loadInventory(e.target.value.trim(), currentStatusFilter);
    }, 300);
  });

  document.getElementById('clear-search-btn').addEventListener('click', () => {
    searchInput.value = '';
    loadInventory('', currentStatusFilter);
  });

  await loadInventory('', '');
});

function setFilter(status, activeBtn) {
  currentStatusFilter = status;
  document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
  activeBtn.classList.add('active');
  const search = document.getElementById('inventory-search').value.trim();
  loadInventory(search, currentStatusFilter);
function formatHostName(dev) {
  if (!dev) return 'Host';
  const h = dev.hostname || dev.device_hostname;
  if (h && h !== 'Unknown' && h !== 'Unknown Hostname' && h !== '—' && h !== 'N/A' && h !== (dev.ip || dev.device_ip)) {
    return h;
  }
  const os = dev.operating_system || dev.os || dev.device_os;
  if (os && os !== 'Generic OS' && os !== 'Unknown' && os !== 'N/A' && os !== '—') {
    return os;
  }
  return dev.ip || dev.device_ip || 'Host';
}

async function loadInventory(search, status) {
  const tbody = document.getElementById('inventory-tbody');
  if (!tbody) return;

  try {
    const devices = await API.getInventoryDevices(search, status);

    // Update Filter Counts
    const upCount = devices.filter(d => d.status === 'up').length;
    const downCount = devices.filter(d => d.status === 'down').length;
    
    const upEl = document.getElementById('up-count');
    const downEl = document.getElementById('down-count');
    if (upEl) upEl.textContent = upCount;
    if (downEl) downEl.textContent = downCount;

    if (devices.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center text-muted py-4">
            <i class="bi bi-hdd-network fs-3 d-block mb-2 text-secondary"></i>
            No discovered systems found matching selection.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = devices.map(device => {
      const isOnline = (device.status || '').toLowerCase() === 'up';
      const lastSeen = formatDate(device.updated_at || device.created_at);
      
      return `
        <tr>
          <td><span class="code-box">${device.ip}</span></td>
          <td class="fw-semibold text-dark">${formatHostName(device)}</td>
          <td class="small text-muted">${device.operating_system || 'Generic OS'}</td>
          <td>
            <span class="status-dot ${isOnline ? 'dot-online' : 'dot-offline'}"></span>
            <span class="small text-uppercase fw-bold ${isOnline ? 'text-success' : 'text-danger'}">${device.status}</span>
          </td>
          <td>
            <span class="badge bg-secondary text-dark border-secondary">${device.open_ports_count || 0} Ports open</span>
          </td>
          <td class="small text-muted">${lastSeen}</td>
          <td class="text-end">
            <div class="d-inline-flex gap-1">
              <button class="btn btn-cyber-outline btn-sm view-device-btn" data-id="${device.id}">
                <i class="bi bi-search me-1"></i>Inspect
              </button>
              <button class="btn btn-cyber-danger btn-sm delete-device-btn" data-id="${device.id}">
                <i class="bi bi-trash"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach Event Listeners
    tbody.querySelectorAll('.view-device-btn').forEach(btn => {
      btn.addEventListener('click', () => openDeviceModal(btn.dataset.id));
    });

    tbody.querySelectorAll('.delete-device-btn').forEach(btn => {
      btn.addEventListener('click', () => handleDeleteDevice(btn.dataset.id));
    });

  } catch (error) {
    showToast(`Failed to load inventory: ${error.message}`, 'danger');
  }
}

async function openDeviceModal(deviceId) {
  const modalBody = document.getElementById('modalDeviceBody');
  modalBody.innerHTML = `<div class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm text-primary me-2"></div> Loading device details...</div>`;
  deviceModalInstance.show();

  try {
    const device = await API.getDeviceDetail(deviceId);

    const portsHtml = device.ports && device.ports.length > 0
      ? device.ports.map(p => `
          <tr>
            <td><span class="code-box">${p.number}/${p.protocol}</span></td>
            <td><span class="badge bg-success-subtle text-success border border-success-subtle">${p.state}</span></td>
            <td class="fw-semibold text-primary">${p.service}</td>
            <td class="small text-muted">${p.product || ''} ${p.version || ''}</td>
          </tr>
        `).join('')
      : `<tr><td colspan="4" class="text-center text-muted py-2">No active ports identified</td></tr>`;

    const findingsHtml = device.recent_findings && device.recent_findings.length > 0
      ? device.recent_findings.map(f => `
          <div class="p-3 mb-2 rounded border bg-light">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="badge-cyber ${getSeverityBadgeClass(f.severity)}">${f.severity} Severity</span>
              <span class="small text-muted">Port ${f.port} (${f.service})</span>
            </div>
            <p class="mb-1 small fw-semibold text-dark">${f.description}</p>
            <p class="mb-0 text-muted" style="font-size:0.8rem;"><i class="bi bi-shield-check text-success me-1"></i> Recommendation: ${f.recommendation}</p>
          </div>
        `).join('')
      : `<p class="text-muted small py-2"><i class="bi bi-check-circle text-success me-1"></i> No active vulnerability findings identified on this host.</p>`;

    modalBody.innerHTML = `
      <div class="row mb-3 g-2">
        <div class="col-md-6">
          <div class="p-3 rounded border bg-light">
            <div class="text-muted small">IP Address</div>
            <div class="fw-bold fs-5 text-dark">${device.ip}</div>
            <div class="text-muted small mt-1">Hostname: ${formatHostName(device)}</div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="p-3 rounded border bg-light">
            <div class="text-muted small">Hardware & OS</div>
            <div class="fw-semibold text-dark">${device.vendor || 'Generic Host'}</div>
            <div class="text-muted small mt-1">OS: ${device.operating_system || 'N/A'}</div>
          </div>
        </div>
      </div>

      <h6 class="fw-bold mb-2 text-dark"><i class="bi bi-diagram-2 me-1"></i> Open Ports & Active Services</h6>
      <div class="table-responsive mb-4">
        <table class="table table-cyber table-sm align-middle mb-0">
          <thead>
            <tr>
              <th>Port</th>
              <th>State</th>
              <th>Service</th>
              <th>Product / Version</th>
            </tr>
          </thead>
          <tbody>${portsHtml}</tbody>
        </table>
      </div>

      <h6 class="fw-bold mb-2 text-dark"><i class="bi bi-bug me-1"></i> Vulnerability Findings</h6>
      <div>${findingsHtml}</div>
    `;

  } catch (error) {
    modalBody.innerHTML = `<div class="alert alert-danger">Error loading device details: ${error.message}</div>`;
  }
}

async function handleDeleteDevice(id) {
  const confirmed = await showConfirm(`Remove Device #${id} from inventory? This cannot be undone.`);
  if (!confirmed) return;
  try {
    await API.deleteDevice(id);
    showToast(`Device #${id} removed from inventory.`, 'success');
    loadInventory(document.getElementById('inventory-search').value.trim(), currentStatusFilter);
  } catch (error) {
    showToast(`Failed to delete device: ${error.message}`, 'danger');
  }
}
