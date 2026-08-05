import { renderNavbar, formatDate, showToast } from './app.js';
import { API } from './api.js';

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

    // 2. Score Circle
    const scoreVal = data.latest_security_score ?? 0;
    const scoreCircle = document.getElementById('score-circle-element');
    const scoreTextStatus = document.getElementById('score-text-status');
    const scoreValueEl = document.getElementById('score-value');

    scoreValueEl.textContent = data.latest_security_score !== null ? scoreVal : '--';

    let scoreColor = '#38bdf8';
    let statusLabel = 'Optimal';

    if (scoreVal >= 80) {
      scoreColor = '#10b981';
      statusLabel = 'Strong Posture';
    } else if (scoreVal >= 60) {
      scoreColor = '#eab308';
      statusLabel = 'Moderate Risk';
    } else if (scoreVal > 0) {
      scoreColor = '#f43f5e';
      statusLabel = 'Critical Risk';
    } else {
      statusLabel = 'No Scans Run';
    }

    if (scoreCircle) {
      scoreCircle.style.setProperty('--score', scoreVal);
      scoreCircle.style.setProperty('--score-color', scoreColor);
    }
    if (scoreTextStatus) {
      scoreTextStatus.textContent = statusLabel;
      scoreTextStatus.style.color = scoreColor;
    }

    // 3. Vulnerability Distribution
    const vulns = data.vulnerability_summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    const totalVulns = vulns.total || 1;

    document.getElementById('count-critical').textContent = vulns.critical;
    document.getElementById('count-high').textContent = vulns.high;
    document.getElementById('count-medium').textContent = vulns.medium;
    document.getElementById('count-low').textContent = vulns.low;

    document.getElementById('bar-critical').style.width = `${(vulns.critical / totalVulns) * 100}%`;
    document.getElementById('bar-high').style.width = `${(vulns.high / totalVulns) * 100}%`;
    document.getElementById('bar-medium').style.width = `${(vulns.medium / totalVulns) * 100}%`;
    document.getElementById('bar-low').style.width = `${(vulns.low / totalVulns) * 100}%`;

    // 4. Recent Audits Table
    renderRecentAudits(data.recent_audits || []);

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
          <i class="bi bi-shield-x fs-3 d-block mb-2 text-secondary"></i>
          No audit scans recorded yet. <a href="scan.html" class="text-info fw-semibold">Launch your first audit</a>.
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
        <span class="badge ${audit.laboratory_security_score >= 80 ? 'bg-safe' : audit.laboratory_security_score >= 60 ? 'bg-medium' : 'bg-critical'}">
          ${audit.laboratory_security_score} / 100
        </span>
      </td>
      <td>
        <span class="badge bg-secondary text-uppercase">${audit.status}</span>
      </td>
      <td class="text-end">
        <a href="audit-details.html?id=${audit.id}" class="btn btn-cyber-outline btn-sm me-1">
          <i class="bi bi-eye me-1"></i> View
        </a>
      </td>
    </tr>
  `).join('');
}
