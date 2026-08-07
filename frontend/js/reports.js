import { renderNavbar, formatDate, showToast } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('reports');
  await loadReports();
});

async function loadReports() {
  const tbody = document.getElementById('reports-tbody');
  if (!tbody) return;

  try {
    const audits = await API.getAudits();
    const completedAudits = audits.filter(a => a.status === 'completed');

    if (completedAudits.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-muted py-4">
            <i class="bi bi-file-earmark-pdf fs-3 d-block mb-2 text-secondary"></i>
            No completed audit reports available yet. <a href="scan.html" class="text-primary fw-semibold">Launch a scan</a>.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = completedAudits.map(audit => {
      const score = audit.laboratory_security_score ?? 0;
      const scoreBadgeClass = score >= 80 ? 'bg-safe' : score >= 60 ? 'bg-medium' : 'bg-critical';
      const pdfUrl = API.downloadAuditPdfUrl(audit.id);

      return `
        <tr>
          <td class="fw-bold">#${audit.id}</td>
          <td><span class="code-box">${audit.target}</span></td>
          <td class="text-muted small">${formatDate(audit.scan_date)}</td>
          <td>
            <span class="badge-cyber ${scoreBadgeClass}">${score} / 100</span>
          </td>
          <td class="text-end">
            <div class="d-inline-flex gap-1">
              <a href="audit-details.html?id=${audit.id}" class="btn btn-cyber-outline btn-sm">
                <i class="bi bi-file-earmark-text me-1"></i>View Report
              </a>
              <a href="${pdfUrl}" target="_blank" class="btn btn-cyber-primary btn-sm">
                <i class="bi bi-file-earmark-pdf me-1"></i>Download PDF
              </a>
            </div>
          </td>
        </tr>
      `;
    }).join('');

  } catch (error) {
    showToast(`Failed to load reports: ${error.message}`, 'danger');
  }
}
