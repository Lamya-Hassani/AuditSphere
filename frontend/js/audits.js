import { renderNavbar, formatDate, showToast } from './app.js';
import { API } from './api.js';

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('audits');
  await loadAudits();
});

async function loadAudits() {
  const tbody = document.getElementById('audits-tbody');
  if (!tbody) return;

  try {
    const audits = await API.getAudits();

    if (audits.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center text-muted py-4">
            <i class="bi bi-shield-x fs-3 d-block mb-2 text-secondary"></i>
            No audit records found. <a href="scan.html" class="text-info">Run a scan now</a>.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = audits.map(audit => {
      const score = audit.laboratory_security_score ?? 0;
      const scoreBadgeClass = score >= 80 ? 'bg-safe' : score >= 60 ? 'bg-medium' : 'bg-critical';
      const executor = audit.executed_by_username || 'System Engine';

      return `
        <tr>
          <td class="fw-bold">#${audit.id}</td>
          <td><span class="code-box">${audit.target}</span></td>
          <td class="text-muted small">${formatDate(audit.scan_date)}</td>
          <td class="small text-uppercase text-info">${audit.scan_type || 'Network Scan'}</td>
          <td>
            <span class="badge ${scoreBadgeClass} fs-6">${score} / 100</span>
          </td>
          <td class="small text-muted">
            <i class="bi bi-person me-1"></i> ${executor}
          </td>
          <td>
            <span class="badge bg-secondary text-uppercase">${audit.status}</span>
          </td>
          <td class="text-end">
            <a href="audit-details.html?id=${audit.id}" class="btn btn-cyber-outline btn-sm me-1" title="View Full Report">
              <i class="bi bi-file-earmark-text me-1"></i> Report
            </a>
            <button class="btn btn-cyber-primary btn-sm me-1 rescan-btn" data-id="${audit.id}" title="Re-run Scan">
              <i class="bi bi-arrow-repeat"></i>
            </button>
            <button class="btn btn-cyber-danger btn-sm delete-audit-btn" data-id="${audit.id}" title="Delete Report">
              <i class="bi bi-trash"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach Action Handlers
    tbody.querySelectorAll('.rescan-btn').forEach(btn => {
      btn.addEventListener('click', () => handleRescan(btn.dataset.id, btn));
    });

    tbody.querySelectorAll('.delete-audit-btn').forEach(btn => {
      btn.addEventListener('click', () => handleDeleteAudit(btn.dataset.id));
    });

  } catch (error) {
    showToast(`Failed to load audit history: ${error.message}`, 'danger');
  }
}

async function handleRescan(auditId, buttonEl) {
  const originalHtml = buttonEl.innerHTML;
  buttonEl.disabled = true;
  buttonEl.innerHTML = `<span class="spinner-border spinner-border-sm" role="status"></span>`;

  try {
    showToast(`Rescan launched for Audit #${auditId}...`, 'info');
    const newAudit = await API.rescanAudit(auditId);
    showToast(`Rescan completed! New Audit #${newAudit.id} generated.`, 'success');
    window.location.href = `audit-details.html?id=${newAudit.id}`;
  } catch (error) {
    showToast(`Rescan failed: ${error.message}`, 'danger');
    buttonEl.disabled = false;
    buttonEl.innerHTML = originalHtml;
  }
}

async function handleDeleteAudit(auditId) {
  if (confirm(`Are you sure you want to delete Audit Report #${auditId}?`)) {
    try {
      await API.deleteAudit(auditId);
      showToast(`Audit Report #${auditId} deleted.`, 'success');
      loadAudits();
    } catch (error) {
      showToast(`Failed to delete audit: ${error.message}`, 'danger');
    }
  }
}
