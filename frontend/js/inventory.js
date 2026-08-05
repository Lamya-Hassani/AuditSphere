import { renderNavbar, showToast, getSeverityBadgeClass } from './app.js';
import { API } from './api.js';

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
}

async function loadInventory(search, status) {
  const tbody = document.getElementById('inventory-tbody');
  if (!tbody) return;

  try {
    const devices = await API.getInventoryDevices(search, status);

    // Update Filter Counts
    const upCount = devices.filter(d => d.status === 'up').length;
    const downCount = devices.filter(d => d.status === 'down').length;
    document.getElementById('up-count').textContent = upCount;
    document.getElementById('down-count').textContent = downCount;

    if (devices.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center text-muted py-4">
            <i class="bi bi-hdd-network fs-3 d-block mb-2 text-secondary"></i>
            No network devices found matching criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = devices.map(device => {
      const riskClass = getSeverityBadgeClass(device.latest_risk_level);
      return `
        <tr>
          <td>
            <span class="status-dot ${device.status === 'up' ? 'dot-online' : 'dot-offline'}"></span>
            <span class="small text-uppercase fw-bold ${device.status === 'up' ? 'text-success' : 'text-danger'}">${device.status}</span>
          </td>
          <td><span class="code-box">${device.ip}</span></td>
          <td class="fw-semibold">${device.hostname || '<span class="text-muted">N/A</span>'}</td>
          <td>
            <div class="small">${device.vendor || 'Unknown Vendor'}</div>
            <div class="text-muted text-uppercase" style="font-size:0.75rem;">${device.mac || 'No MAC'}</div>
          </td>
          <td class="small text-muted">${device.operating_system || 'Generic OS'}</td>
          <td>
            <span class="badge bg-secondary">${device.open_ports_count || 0} Open Ports</span>
          </td>
          <td>
            <span class="badge ${riskClass}">${device.latest_risk_level || 'Unknown'}</span>
          </td>
          <td class="text-end">
            <button class="btn btn-cyber-outline btn-sm me-1 view-device-btn" data-id="${device.id}">
              <i class="bi bi-search me-1"></i> Inspect
            </button>
            <button class="btn btn-cyber-danger btn-sm delete-device-btn" data-id="${device.id}">
              <i class="bi bi-trash"></i>
            </button>
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
  modalBody.innerHTML = `<div class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm text-info me-2"></div> Loading device telemetry...</div>`;
  deviceModalInstance.show();

  try {
    const device = await API.getDeviceDetail(deviceId);

    const portsHtml = device.ports && device.ports.length > 0
      ? device.ports.map(p => `
          <tr>
            <td><span class="code-box">${p.number}/${p.protocol}</span></td>
            <td><span class="badge bg-safe">${p.state}</span></td>
            <td class="fw-semibold text-info">${p.service}</td>
            <td class="small text-muted">${p.product || ''} ${p.version || ''}</td>
          </tr>
        `).join('')
      : `<tr><td colspan="4" class="text-center text-muted py-2">No open ports detected</td></tr>`;

    const findingsHtml = device.recent_findings && device.recent_findings.length > 0
      ? device.recent_findings.map(f => `
          <div class="p-3 mb-2 rounded-3 border" style="background:rgba(255,255,255,0.02); border-color:rgba(255,255,255,0.08)!important;">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="badge ${getSeverityBadgeClass(f.severity)}">${f.severity} Severity</span>
              <span class="small text-muted">Port ${f.port} (${f.service})</span>
            </div>
            <p class="mb-1 small fw-semibold">${f.description}</p>
            <p class="mb-0 text-muted" style="font-size:0.8rem;"><i class="bi bi-shield-check text-success me-1"></i> Recommendation: ${f.recommendation}</p>
          </div>
        `).join('')
      : `<p class="text-muted small">No active security findings recorded for this device.</p>`;

    modalBody.innerHTML = `
      <div class="row mb-3 g-2">
        <div class="col-md-6">
          <div class="p-3 rounded-3" style="background:rgba(255,255,255,0.03);">
            <div class="text-muted small">IP Address</div>
            <div class="fw-bold fs-5 text-info">${device.ip}</div>
            <div class="text-muted small mt-1">Hostname: ${device.hostname || 'N/A'}</div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="p-3 rounded-3" style="background:rgba(255,255,255,0.03);">
            <div class="text-muted small">MAC / Vendor</div>
            <div class="fw-semibold">${device.vendor || 'Generic Host'}</div>
            <div class="text-muted small mt-1">MAC: ${device.mac || 'N/A'}</div>
          </div>
        </div>
      </div>

      <h6 class="fw-bold mb-2 text-info"><i class="bi bi-diagram-2 me-1"></i> Open Ports & Services</h6>
      <div class="table-responsive mb-4">
        <table class="table table-cyber table-sm align-middle">
          <thead>
            <tr>
              <th>Port</th>
              <th>State</th>
              <th>Service</th>
              <th>Product Version</th>
            </tr>
          </thead>
          <tbody>${portsHtml}</tbody>
        </table>
      </div>

      <h6 class="fw-bold mb-2 text-warning"><i class="bi bi-bug me-1"></i> Security Vulnerabilities</h6>
      <div>${findingsHtml}</div>
    `;

  } catch (error) {
    modalBody.innerHTML = `<div class="alert alert-danger">Error loading device detail: ${error.message}</div>`;
  }
}

async function handleDeleteDevice(id) {
  if (confirm(`Are you sure you want to remove Device #${id} from inventory?`)) {
    try {
      await API.deleteDevice(id);
      showToast(`Device #${id} removed from inventory`, 'success');
      loadInventory(document.getElementById('inventory-search').value.trim(), currentStatusFilter);
    } catch (error) {
      showToast(`Failed to delete device: ${error.message}`, 'danger');
    }
  }
}
