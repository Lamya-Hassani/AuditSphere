import { renderNavbar, formatDate, showToast, showConfirm, getSeverityBadgeClass } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

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
    const scanType = audit.scan_type || 'Laboratory Network Audit';

    let mode = 'full';
    if (scanType === 'Host Discovery')      mode = 'discovery';
    else if (scanType === 'Port Sweep')     mode = 'ports';

    document.getElementById('page-title').textContent = `Audit Report #${audit.id} — ${scanType}`;

    const downloadPdfBtn = document.getElementById('download-pdf-btn');
    if (downloadPdfBtn) downloadPdfBtn.href = API.downloadAuditPdfUrl(audit.id);

    document.getElementById('meta-target').textContent   = audit.target;
    document.getElementById('meta-date').textContent     = formatDate(audit.scan_date);
    document.getElementById('meta-type').textContent     = scanType;
    document.getElementById('meta-scanner').textContent  = audit.scanner_version || 'Nmap Engine';
    document.getElementById('meta-rules').textContent    = `v${audit.rules_version || '1.0'}`;
    document.getElementById('meta-executor').textContent = audit.executed_by_username || 'System Engine';

    // Score Card
    const scoreSection = document.getElementById('score-section');
    if (scoreSection) {
      if (mode === 'full') {
        scoreSection.classList.remove('d-none');
        const score = audit.laboratory_security_score ?? 0;
        document.getElementById('score-value').textContent = score;

        let scoreColor = '#2563eb';
        let statusLabel = 'Optimal';
        if (score >= 80)     { scoreColor = '#10b981'; statusLabel = 'Strong Posture'; }
        else if (score >= 60) { scoreColor = '#f59e0b'; statusLabel = 'Moderate Risk'; }
        else if (score > 0)  { scoreColor = '#ef4444'; statusLabel = 'Critical Risk'; }
        else                  { statusLabel = 'No Data'; }

        const scoreCircle = document.getElementById('score-circle-element');
        if (scoreCircle) {
          scoreCircle.style.setProperty('--score', score);
          scoreCircle.style.setProperty('--score-color', scoreColor);
        }
        const scoreStatusText = document.getElementById('score-text-status');
        if (scoreStatusText) {
          scoreStatusText.textContent = statusLabel;
          scoreStatusText.style.color = scoreColor;
        }
      } else {
        scoreSection.classList.add('d-none');
      }
    }

    // Statistics Card
    const statsSection = document.getElementById('stats-section');
    if (statsSection) {
      if (mode === 'full') {
        statsSection.classList.remove('d-none');
        const stats = audit.statistics || { critical: 0, high: 0, medium: 0, low: 0 };
        document.getElementById('stat-critical').textContent = stats.critical ?? 0;
        document.getElementById('stat-high').textContent     = stats.high     ?? 0;
        document.getElementById('stat-medium').textContent   = stats.medium   ?? 0;
        document.getElementById('stat-low').textContent      = stats.low      ?? 0;
      } else {
        statsSection.classList.add('d-none');
      }
    }

    // Recommendations List
    const recsSection = document.getElementById('recommendations-section');
    if (recsSection) {
      if (mode === 'full') {
        recsSection.classList.remove('d-none');
        const recsList = document.getElementById('recommendations-list');
        if (audit.recommendations && audit.recommendations.length > 0) {
          recsList.innerHTML = audit.recommendations.map(r => `
            <li class="list-group-item bg-transparent text-dark border-0 py-2 ps-0">
              ${r.text}
            </li>
          `).join('');
        } else {
          recsList.innerHTML = `<li class="list-group-item bg-transparent text-muted border-0 py-2 ps-0">No remediation steps generated.</li>`;
        }
      } else {
        recsSection.classList.add('d-none');
      }
    }

    // Historical Comparison
    renderComparison(audit.comparison_data || audit.comparison);

    // Devices & Findings
    renderDevices(audit.devices || [], mode);

  } catch (error) {
    showToast(`Failed to load audit details: ${error.message}`, 'danger');
  }
}

function renderComparison(cmp) {
  const card = document.getElementById('comparison-card');
  const container = document.getElementById('comparison-content');
  if (!card || !container) return;

  if (!cmp || !cmp.summary) {
    card.classList.add('d-none');
    return;
  }

  card.classList.remove('d-none');

  const isPositive = cmp.score_delta >= 0;
  const deltaBadgeClass = isPositive ? 'bg-success-subtle text-success border-success-subtle' : 'bg-danger-subtle text-danger border-danger-subtle';
  const deltaIcon = isPositive ? 'bi-arrow-up-right' : 'bi-arrow-down-right';
  const deltaText = isPositive ? `+${cmp.score_delta}` : `${cmp.score_delta}`;

  const newHostsText = cmp.new_hosts?.length > 0 ? cmp.new_hosts.join(', ') : 'None';
  const removedHostsText = cmp.removed_hosts?.length > 0 ? cmp.removed_hosts.join(', ') : 'None';

  container.innerHTML = `
    <div class="alert alert-info py-2 px-3 mb-3 small d-flex align-items-center gap-2">
      <i class="bi bi-info-circle-fill text-info fs-5"></i>
      <span>${cmp.summary}</span>
    </div>

    <div class="row g-2 text-center mb-3">
      <div class="col-4">
        <div class="p-2 border rounded bg-light">
          <div class="text-muted small">Previous Score</div>
          <div class="fw-bold fs-5 text-dark">${cmp.previous_score ?? 'N/A'}</div>
        </div>
      </div>
      <div class="col-4">
        <div class="p-2 border rounded bg-light">
          <div class="text-muted small">Current Score</div>
          <div class="fw-bold fs-5 text-primary">${cmp.current_score ?? 'N/A'}</div>
        </div>
      </div>
      <div class="col-4">
        <div class="p-2 border rounded bg-light">
          <div class="text-muted small">Security Delta</div>
          <div class="fw-bold fs-5">
            <span class="badge ${deltaBadgeClass}">
              <i class="bi ${deltaIcon} me-1"></i>${deltaText} pts
            </span>
          </div>
        </div>
      </div>
    </div>

    <div class="row g-2 small text-muted border-top pt-2">
      <div class="col-md-6">
        <strong class="text-dark">New Vulnerabilities:</strong> <span class="text-danger">+${cmp.new_findings_count ?? 0}</span> | 
        <strong class="text-dark">Resolved:</strong> <span class="text-success">-${cmp.resolved_findings_count ?? 0}</span>
      </div>
      <div class="col-md-6 text-md-end">
        <strong class="text-dark">Risk Transition:</strong> ${cmp.risk_evolution?.previous || 'N/A'} &rarr; <span class="fw-bold text-dark">${cmp.risk_evolution?.current || 'N/A'}</span>
      </div>
      <div class="col-12">
        <strong class="text-dark">Host Delta:</strong> Added: <code class="text-dark">${newHostsText}</code> | Removed: <code class="text-dark">${removedHostsText}</code>
      </div>
    </div>
  `;
}

function formatHostLabel(dev) {
  const ip = dev.device_ip || dev.ip || '';
  const h = dev.device_hostname || dev.hostname;
  if (h && h !== 'Unknown' && h !== 'Unknown Hostname' && h !== '—' && h !== 'N/A' && h !== ip) {
    return h;
  }
  const os = dev.device_os || dev.operating_system || dev.os;
  if (os && os !== 'Generic OS' && os !== 'Unknown' && os !== 'N/A' && os !== '—') {
    return os;
  }
  return ip || 'Host';
}

function renderDevices(devices, mode) {
  const container = document.getElementById('devices-container');
  const sectionTitle = document.getElementById('devices-section-title');
  if (!container) return;

  if (devices.length === 0) {
    container.innerHTML = `<div class="text-center py-4 text-muted">No hosts discovered during this scan.</div>`;
    return;
  }

  if (mode === 'discovery') {
    if (sectionTitle) sectionTitle.textContent = `Discovered Hosts (${devices.length})`;
    container.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>MAC Address</th>
              <th>Vendor</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${devices.map(d => `
              <tr>
                <td><code>${d.device_ip || d.ip || '—'}</code></td>
                <td class="fw-semibold">${formatHostLabel(d)}</td>
                <td><code class="text-muted">${d.device_mac || d.mac || '—'}</code></td>
                <td>${d.device_vendor || d.vendor || '—'}</td>
                <td><span class="badge-cyber badge-safe">Up</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
    return;
  }

  if (mode === 'ports') {
    if (sectionTitle) sectionTitle.textContent = `Scanned Hosts & Open Ports (${devices.length})`;
    container.innerHTML = devices.map((auditDevice, index) => {
      const ip = auditDevice.device_ip || auditDevice.ip || 'Unknown';
      const label = formatHostLabel(auditDevice);
      const os = auditDevice.device_os || auditDevice.os || '—';
      const ports = auditDevice.ports || [];

      const portsHtml = ports.length > 0
        ? `<table class="table table-sm table-hover mb-0 mt-2">
             <thead class="table-light">
               <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
             </thead>
             <tbody>
               ${ports.map(p => `
                 <tr>
                   <td><code>${p.number}</code></td>
                   <td>${p.protocol}</td>
                   <td>${p.service || '—'}</td>
                   <td>${p.product || '—'}</td>
                   <td>${p.version || '—'}</td>
                 </tr>
               `).join('')}
             </tbody>
           </table>`
        : `<div class="text-muted small py-2"><i class="bi bi-info-circle me-1"></i>No open ports found on this host.</div>`;

      const hostTitle = (label && label !== ip && label !== 'Host')
        ? `<span class="fw-semibold text-dark">(${label})</span>`
        : '';

      return `
        <div class="card mb-3 border-secondary-subtle">
          <div class="card-header bg-light d-flex justify-content-between align-items-center"
               style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#device-collapse-${index}">
            <div>
              <span class="code-box me-2">${ip}</span>
              ${hostTitle}
            </div>
            <div class="d-flex align-items-center gap-2">
              <span class="small text-muted">${ports.length} open port${ports.length !== 1 ? 's' : ''}</span>
              <i class="bi bi-chevron-down text-muted"></i>
            </div>
          </div>
          <div id="device-collapse-${index}" class="collapse show">
            <div class="card-body p-3 bg-white">
              <div class="mb-2 small text-muted pb-2 border-bottom">
                OS: ${os} | MAC: ${auditDevice.device_mac || auditDevice.mac || 'N/A'} | Vendor: ${auditDevice.device_vendor || auditDevice.vendor || 'Unknown'}
              </div>
              ${portsHtml}
            </div>
          </div>
        </div>
      `;
    }).join('');
    return;
  }

  // Full Audit Mode — render detailed Findings with CVE and Source tags
  if (sectionTitle) sectionTitle.textContent = `Scanned Devices (${devices.length})`;

  container.innerHTML = devices.map((auditDevice, index) => {
    const dev = auditDevice.device_ip
      ? { ip: auditDevice.device_ip, hostname: auditDevice.device_hostname, operating_system: auditDevice.device_os, mac: auditDevice.device_mac, vendor: auditDevice.device_vendor }
      : (auditDevice.device || {});

    const riskBadgeClass = getSeverityBadgeClass(auditDevice.risk_level);
    const findings = auditDevice.findings || [];
    const devIp = dev.ip || 'Unknown IP';
    const devLabel = formatHostLabel(dev);
    const devTitle = (devLabel && devLabel !== devIp && devLabel !== 'Host')
      ? `<span class="fw-semibold text-dark">(${devLabel})</span>`
      : '';

    const findingsHtml = findings.length > 0
      ? findings.map(f => {
          const isCve = !!f.cve_id;
          const cveTag = isCve
            ? `<span class="badge bg-danger-subtle text-danger border border-danger-subtle fw-bold me-2"><i class="bi bi-bug-fill me-1"></i>${f.cve_id} (CVSS ${f.cvss_score || 'N/A'})</span>`
            : '';
          const sourceTag = f.source === 'nse'
            ? `<span class="badge bg-info-subtle text-info border border-info-subtle me-2">NSE Script</span>`
            : '';

          return `
            <div class="p-3 mb-3 rounded border bg-light">
              <div class="d-flex flex-wrap justify-content-between align-items-center mb-2 gap-1">
                <div>
                  <span class="badge-cyber ${getSeverityBadgeClass(f.severity)} me-2">${f.severity}</span>
                  ${cveTag}
                  ${sourceTag}
                  <span class="fw-bold text-dark me-1">${f.service}</span>
                  <span class="text-muted small">(Port ${f.port})</span>
                </div>
                <span class="badge bg-secondary text-dark border-secondary">-${f.points} pts</span>
              </div>
              
              <p class="mb-2 text-dark small">${f.description}</p>
              
              <div class="p-2 rounded bg-white border small text-muted">
                <strong class="text-dark d-block mb-1"><i class="bi bi-shield-check text-success me-1"></i>Remediation Directive:</strong>
                ${f.recommendation}
              </div>
            </div>
          `;
        }).join('')
      : `<div class="text-muted small py-2"><i class="bi bi-check-circle text-success me-1"></i>No security findings identified on this host.</div>`;

    return `
      <div class="card mb-3 border-secondary-subtle">
        <div class="card-header bg-light d-flex justify-content-between align-items-center"
             style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#device-collapse-${index}">
          <div>
            <span class="code-box me-2">${devIp}</span>
            ${devTitle}
          </div>
          <div class="d-flex align-items-center gap-2">
            <span class="small text-muted me-2">Risk Score: ${auditDevice.risk_score ?? 0}</span>
            <span class="badge-cyber ${riskBadgeClass} me-2">${auditDevice.risk_level || 'N/A'}</span>
            <i class="bi bi-chevron-down text-muted"></i>
          </div>
        </div>
        <div id="device-collapse-${index}" class="collapse show">
          <div class="card-body p-3 bg-white">
            <div class="mb-3 small text-muted pb-2 border-bottom">
              OS: ${dev.operating_system || dev.os || 'Generic OS'} | Vendor: ${dev.vendor || 'Unknown'} | MAC: ${dev.mac || 'N/A'}
            </div>
            <h6 class="fw-bold text-muted small text-uppercase mb-2">
              Host Vulnerability & Threat Findings (${findings.length})
            </h6>
            ${findingsHtml}
          </div>
        </div>
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
    showToast('Re-scan completed!', 'success');
    window.location.href = `audit-details.html?id=${newAudit.id}`;
  } catch (error) {
    showToast(`Rescan failed: ${error.message}`, 'danger');
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-arrow-repeat me-1"></i> Re-run Audit`;
  }
}

async function handleDelete() {
  if (!currentAuditId) return;
  const confirmed = await showConfirm(`Delete Audit Report #${currentAuditId}? This action cannot be undone.`);
  if (!confirmed) return;
  try {
    await API.deleteAudit(currentAuditId);
    showToast(`Audit Report #${currentAuditId} deleted.`, 'success');
    setTimeout(() => window.location.href = 'audits.html', 1000);
  } catch (error) {
    showToast(`Failed to delete audit: ${error.message}`, 'danger');
  }
}
