import { renderNavbar, formatDate, showToast, getSeverityBadgeClass } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('dashboard');

  const quickScanForm = document.getElementById('quick-scan-form');
  if (quickScanForm) {
    quickScanForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const target = document.getElementById('quick-target').value.trim();
      if (target) {
        window.location.href = `scan.html?target=${encodeURIComponent(target)}`;
      }
    });
  }

  await loadDashboardData();
});

async function loadDashboardData() {
  try {
    const data = await API.getDashboardSummary();

    // 1. Metric Cards
    document.getElementById('metric-total-audits').textContent = data.total_audits ?? 0;
    document.getElementById('metric-total-devices').textContent = data.total_devices ?? 0;
    document.getElementById('metric-online-devices').textContent = data.online_devices ?? 0;
    document.getElementById('metric-avg-score').textContent = `${data.average_security_score ?? 0}%`;

    const vulns = data.vulnerability_summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    document.getElementById('metric-critical-high').textContent = (vulns.critical ?? 0) + (vulns.high ?? 0);

    // 2. Vulnerability Distribution
    const totalVulns = vulns.total || 1;

    document.getElementById('count-critical').textContent = vulns.critical;
    document.getElementById('count-high').textContent = vulns.high;
    document.getElementById('count-medium').textContent = vulns.medium;
    document.getElementById('count-low').textContent = vulns.low;

    document.getElementById('bar-critical').style.width = `${(vulns.critical / totalVulns) * 100}%`;
    document.getElementById('bar-high').style.width = `${(vulns.high / totalVulns) * 100}%`;
    document.getElementById('bar-medium').style.width = `${(vulns.medium / totalVulns) * 100}%`;
    document.getElementById('bar-low').style.width = `${(vulns.low / totalVulns) * 100}%`;

    // 3. Recent Audits Table
    renderRecentAudits(data.recent_audits || []);

    // 4. Security Score Trend & Most Vulnerable Devices
    await loadTrendAndVulnerableDevices();

  } catch (error) {
    showToast(`Failed to load dashboard: ${error.message}`, 'danger');
  }
}

function renderRecentAudits(audits) {
  const tbody = document.getElementById('recent-audits-body');
  if (!tbody) return;

  if (audits.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center text-muted py-4">
          No audit scans recorded yet. <a href="scan.html" class="text-primary fw-semibold">Launch your first audit</a>.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = audits.map(audit => `
    <tr>
      <td>
        <span class="code-box">${audit.target}</span>
      </td>
      <td class="text-muted small">${formatDate(audit.scan_date)}</td>
      <td>
        <span class="badge-cyber ${audit.laboratory_security_score >= 80 ? 'bg-safe' : audit.laboratory_security_score >= 60 ? 'bg-medium' : 'bg-critical'}">
          ${audit.laboratory_security_score} / 100
        </span>
      </td>
      <td>
        <span class="badge-cyber bg-secondary">${audit.status}</span>
      </td>
      <td class="text-end">
        <a href="audit-details.html?id=${audit.id}" class="btn btn-cyber-outline btn-sm me-1">
          <i class="bi bi-eye"></i> View
        </a>
      </td>
    </tr>
  `).join('');
}

async function loadTrendAndVulnerableDevices() {
  try {
    // Trend List
    const scoreTrendList = document.getElementById('score-trend-list');
    const audits = await API.getAudits();
    if (scoreTrendList) {
      if (audits.length === 0) {
        scoreTrendList.innerHTML = `<div class="text-muted small py-2 text-center">No trend data.</div>`;
      } else {
        // Take latest 5 completed audits
        const completedAudits = audits.filter(a => a.status === 'completed').slice(0, 5);
        scoreTrendList.innerHTML = completedAudits.map(audit => `
          <div class="d-flex justify-content-between align-items-center border-bottom pb-2 mb-2">
            <div>
              <span class="small text-muted d-block">${formatDate(audit.scan_date)}</span>
              <span class="code-box small">${audit.target}</span>
            </div>
            <span class="fw-bold text-dark fs-6">${audit.laboratory_security_score}/100</span>
          </div>
        `).join('');
      }
    }

    // Vulnerable Devices
    const vulnerableDevicesBody = document.getElementById('vulnerable-devices-body');
    if (vulnerableDevicesBody) {
      const devices = await API.getInventoryDevices();
      
      // Filter out clean/unknown or sort by vulnerability level
      // Level hierarchy: critical > high > medium > low > unknown
      const levelWeight = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0 };
      const sortedDevices = [...devices].sort((a, b) => {
        const weightA = levelWeight[a.latest_risk_level?.toLowerCase()] || 0;
        const weightB = levelWeight[b.latest_risk_level?.toLowerCase()] || 0;
        return weightB - weightA;
      }).slice(0, 5); // top 5

      if (sortedDevices.length === 0) {
        vulnerableDevicesBody.innerHTML = `
          <tr>
            <td colspan="5" class="text-center text-muted py-3">No inventory devices recorded.</td>
          </tr>
        `;
        return;
      }

      vulnerableDevicesBody.innerHTML = sortedDevices.map(device => {
        const riskLevel = device.latest_risk_level || 'unknown';
        const riskClass = getSeverityBadgeClass(riskLevel);
        return `
          <tr>
            <td><span class="code-box">${device.ip}</span></td>
            <td class="fw-semibold">${device.hostname || 'N/A'}</td>
            <td class="small text-muted">${device.operating_system || 'Generic OS'}</td>
            <td class="small text-muted">${device.open_ports_count || 0} Ports open</td>
            <td><span class="badge-cyber ${riskClass}">${riskLevel}</span></td>
          </tr>
        `;
      }).join('');
    }
  } catch (error) {
    console.error('Error loading trend and vulnerable devices', error);
  }
}
