import { renderNavbar, formatDate, showToast, getSeverityBadgeClass } from './app.js';
import { API } from './api.js';

let currentAuditId = null;

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('audits');

  const urlParams = new URLSearchParams(window.location.search);
  currentAuditId = urlParams.get('id');

  if (!currentAuditId) {
    showToast('No Audit ID specified', 'danger');
    setTimeout(() => window.location.href = 'audits.html', 1500);
    return;
  }

  document.getElementById('rescan-current-btn')?.addEventListener('click', handleRescan);
  document.getElementById('delete-current-btn')?.addEventListener('click', handleDelete);

  await loadAuditDetail(currentAuditId);
});

async function loadAuditDetail(id) {
  try {
    const audit = await API.getAuditDetail(id);

    // 1. Hero Banner
    const score = audit.laboratory_security_score ?? 0;
    const scoreBadgeClass = score >= 80 ? 'bg-safe' : score >= 60 ? 'bg-medium' : 'bg-critical';

    document.getElementById('report-hero').innerHTML = `
      <div class="row align-items-center">
        <div class="col-md-8">
          <div class="d-flex align-items-center gap-3 mb-2">
            <h2 class="fw-bold mb-0">Audit Report #${audit.id}</h2>
            <span class="badge ${scoreBadgeClass} fs-5">${score} / 100</span>
            <span class="badge bg-secondary text-uppercase">${audit.status}</span>
          </div>
          <p class="text-muted mb-2">Target Network / Host: <span class="code-box fs-6">${audit.target}</span></p>
          <div class="d-flex flex-wrap gap-4 text-muted small">
            <span><i class="bi bi-calendar3 me-1"></i> Scan Date: ${formatDate(audit.scan_date)}</span>
            <span><i class="bi bi-cpu me-1"></i> Scanner: ${audit.scanner_version || 'Nmap Engine'}</span>
            <span><i class="bi bi-shield me-1"></i> Rules: v${audit.rules_version || '1.0'}</span>
            <span><i class="bi bi-person me-1"></i> Executed by: ${audit.executed_by_username || 'System Administrator'}</span>
          </div>
        </div>
        <div class="col-md-4 text-md-end mt-3 mt-md-0">
          <div class="score-circle mx-auto ms-md-auto" style="--score:${score}; --score-color:${score >= 80 ? '#10b981' : score >= 60 ? '#eab308' : '#f43f5e'};">
            <div class="score-inner">
              <span class="score-val">${score}</span>
              <span class="score-lbl">Score</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // 2. Statistics
    const stats = audit.statistics || { critical: 0, high: 0, medium: 0, low: 0 };
    document.getElementById('stat-critical').textContent = stats.critical ?? 0;
    document.getElementById('stat-high').textContent = stats.high ?? 0;
    document.getElementById('stat-medium').textContent = stats.medium ?? 0;
    document.getElementById('stat-low').textContent = stats.low ?? 0;

    // 3. Recommendations
    const recsList = document.getElementById('recommendations-list');
    if (audit.recommendations && audit.recommendations.length > 0) {
      recsList.innerHTML = audit.recommendations.map(r => `
        <li class="list-group-item bg-transparent text-white border-secondary py-2 d-flex align-items-start gap-2">
          <i class="bi bi-check2-circle text-success fs-5"></i>
          <span>${r.text}</span>
        </li>
      `).join('');
    } else {
      recsList.innerHTML = `<li class="list-group-item bg-transparent text-muted border-secondary py-2">No recommendations available.</li>`;
    }

    // 4. Scanned Devices Breakdown
    renderScannedDevices(audit.devices || []);

  } catch (error) {
    showToast(`Failed to load audit details: ${error.message}`, 'danger');
  }
}

function renderScannedDevices(devices) {
  const container = document.getElementById('devices-container');
  if (!container) return;

  if (devices.length === 0) {
    container.innerHTML = `<div class="text-center py-4 text-muted">No hosts discovered during this audit run.</div>`;
    return;
  }

  container.innerHTML = devices.map(auditDevice => {
    const dev = auditDevice.device_ip ? { ip: auditDevice.device_ip, hostname: auditDevice.device_hostname } : (auditDevice.device || {});
    const riskBadgeClass = getSeverityBadgeClass(auditDevice.risk_level);
    const findings = auditDevice.findings || [];

    const findingsHtml = findings.length > 0
      ? findings.map(f => `
          <div class="p-3 mb-2 rounded-3 border" style="background:rgba(255,255,255,0.02); border-color:rgba(255,255,255,0.08)!important;">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <div>
                <span class="badge ${getSeverityBadgeClass(f.severity)} me-2">${f.severity}</span>
                <span class="fw-bold">${f.service}</span> <span class="text-muted small">(Port ${f.port})</span>
              </div>
              <span class="badge bg-dark text-muted border border-secondary">-${f.points} pts</span>
            </div>
            <p class="mb-1 small text-light">${f.description}</p>
            <p class="mb-0 text-muted" style="font-size:0.8rem;">
              <i class="bi bi-shield-check text-success me-1"></i> Remediation: ${f.recommendation}
            </p>
          </div>
        `).join('')
      : `<div class="text-muted small py-2"><i class="bi bi-check-circle text-success me-1"></i> Clean! No vulnerability findings identified on this host.</div>`;

    return `
      <div class="cyber-card p-3 mb-3" style="background:rgba(255,255,255,0.02);">
        <div class="d-flex flex-wrap align-items-center justify-content-between mb-3 border-bottom border-secondary pb-2">
          <div>
            <span class="code-box fs-6 me-2">${dev.ip || 'Unknown IP'}</span>
            <span class="fw-semibold text-white">${dev.hostname || 'Host'}</span>
          </div>
          <div class="d-flex align-items-center gap-2">
            <span class="small text-muted">Risk Score: ${auditDevice.risk_score}</span>
            <span class="badge ${riskBadgeClass}">${auditDevice.risk_level}</span>
          </div>
        </div>

        <h6 class="fw-bold text-info mb-2 small text-uppercase">Findings (${findings.length})</h6>
        ${findingsHtml}
      </div>
    `;
  }).join('');
}

async function handleRescan() {
  if (!currentAuditId) return;
  const btn = document.getElementById('rescan-current-btn');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Rescanning...`;

  try {
    const newAudit = await API.rescanAudit(currentAuditId);
    showToast(`Audit re-run successful!`, 'success');
    window.location.href = `audit-details.html?id=${newAudit.id}`;
  } catch (error) {
    showToast(`Rescan failed: ${error.message}`, 'danger');
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-arrow-repeat"></i> Re-run Audit`;
  }
}

async function handleDelete() {
  if (!currentAuditId) return;
  if (confirm(`Are you sure you want to delete Audit Report #${currentAuditId}?`)) {
    try {
      await API.deleteAudit(currentAuditId);
      showToast(`Audit Report #${currentAuditId} deleted.`, 'success');
      setTimeout(() => window.location.href = 'audits.html', 1000);
    } catch (error) {
      showToast(`Failed to delete audit: ${error.message}`, 'danger');
    }
  }
}
