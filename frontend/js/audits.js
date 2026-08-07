import { renderNavbar, formatDate, showToast, showConfirm } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

let allAudits = [];
let filteredAudits = [];
let currentPage = 1;
const itemsPerPage = 10;
let currentSortField = 'date';
let currentSortOrder = 'desc';
let searchQuery = '';

document.addEventListener('DOMContentLoaded', async () => {
  renderNavbar('audits');
  await initAuditHistory();
});

async function initAuditHistory() {
  const searchInput = document.getElementById('audit-search');
  const clearSearchBtn = document.getElementById('clear-search-btn');

  // Search trigger
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    currentPage = 1;
    applyFilterAndSort();
  });

  // Clear search trigger
  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    searchQuery = '';
    currentPage = 1;
    applyFilterAndSort();
  });

  // Sorting event handlers
  document.getElementById('sort-date').addEventListener('click', () => handleSortClick('date'));
  document.getElementById('sort-target').addEventListener('click', () => handleSortClick('target'));
  document.getElementById('sort-devices').addEventListener('click', () => handleSortClick('devices'));
  document.getElementById('sort-score').addEventListener('click', () => handleSortClick('score'));

  // Load original data
  await loadAudits();
}

async function loadAudits() {
  try {
    allAudits = await API.getAudits();
    applyFilterAndSort();
  } catch (error) {
    showToast(`Failed to load audit history: ${error.message}`, 'danger');
  }
}

function getAuditRiskLevel(audit) {
  if (!audit.devices || audit.devices.length === 0) return 'Safe';
  const levels = audit.devices.map(d => {
    const dev = d.device || {};
    return (d.risk_level || '').toLowerCase();
  });
  if (levels.includes('critical')) return 'Critical';
  if (levels.includes('high')) return 'High';
  if (levels.includes('medium')) return 'Medium';
  if (levels.includes('low')) return 'Low';
  return 'Safe';
}

function getRiskBadgeClass(level) {
  switch (level.toLowerCase()) {
    case 'critical': return 'bg-critical';
    case 'high': return 'bg-high';
    case 'medium': return 'bg-medium';
    case 'low': return 'bg-low';
    default: return 'bg-safe';
  }
}

function handleSortClick(field) {
  if (currentSortField === field) {
    currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    currentSortField = field;
    currentSortOrder = 'desc'; // default to descending for numbers/dates
  }
  updateSortIcons();
  applyFilterAndSort();
}

function updateSortIcons() {
  const fields = ['date', 'target', 'devices', 'score'];
  fields.forEach(f => {
    const icon = document.getElementById(`sort-icon-${f}`);
    if (!icon) return;
    if (f === currentSortField) {
      icon.className = `bi bi-arrow-${currentSortOrder === 'asc' ? 'up' : 'down'} text-primary`;
    } else {
      icon.className = 'bi bi-arrow-down-up ms-1 text-muted';
    }
  });
}

function applyFilterAndSort() {
  // 1. Filter
  filteredAudits = allAudits.filter(audit => {
    const targetMatch = audit.target.toLowerCase().includes(searchQuery.toLowerCase());
    const statusMatch = audit.status.toLowerCase().includes(searchQuery.toLowerCase());
    return targetMatch || statusMatch;
  });

  // 2. Sort
  filteredAudits.sort((a, b) => {
    let valA, valB;
    
    switch (currentSortField) {
      case 'date':
        valA = new Date(a.scan_date).getTime();
        valB = new Date(b.scan_date).getTime();
        break;
      case 'target':
        valA = a.target.toLowerCase();
        valB = b.target.toLowerCase();
        break;
      case 'devices':
        valA = a.statistics?.devices || 0;
        valB = b.statistics?.devices || 0;
        break;
      case 'score':
        valA = a.laboratory_security_score ?? 0;
        valB = b.laboratory_security_score ?? 0;
        break;
      default:
        valA = 0;
        valB = 0;
    }

    if (valA < valB) return currentSortOrder === 'asc' ? -1 : 1;
    if (valA > valB) return currentSortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  // Update total counts display
  document.getElementById('audit-total-count').textContent = filteredAudits.length;

  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('audits-tbody');
  if (!tbody) return;

  if (filteredAudits.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center text-muted py-4">
          <i class="bi bi-shield-exclamation fs-3 d-block mb-2 text-secondary"></i>
          No audit records found matching search criteria.
        </td>
      </tr>
    `;
    updatePagination(0);
    return;
  }

  // Calculate slice
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedItems = filteredAudits.slice(startIndex, startIndex + itemsPerPage);

  tbody.innerHTML = paginatedItems.map(audit => {
    const score = audit.laboratory_security_score ?? 0;
    const scoreBadgeClass = score >= 80 ? 'bg-safe' : score >= 60 ? 'bg-medium' : 'bg-critical';
    const risk = getAuditRiskLevel(audit);
    const riskBadgeClass = getRiskBadgeClass(risk);
    const deviceCount = audit.statistics?.devices ?? (audit.devices?.length ?? 0);
    const pdfUrl = API.downloadAuditPdfUrl(audit.id);

    return `
      <tr>
        <td class="text-muted small">${formatDate(audit.scan_date)}</td>
        <td><span class="code-box">${audit.target}</span></td>
        <td>
          <span class="fw-semibold">${deviceCount}</span> hosts
        </td>
        <td>
          <span class="badge-cyber ${scoreBadgeClass}">${score} / 100</span>
        </td>
        <td>
          <span class="badge-cyber ${riskBadgeClass}">${risk}</span>
        </td>
        <td>
          <span class="badge-cyber bg-secondary text-uppercase">${audit.status}</span>
        </td>
        <td class="text-end">
          <div class="d-inline-flex gap-1">
            <a href="audit-details.html?id=${audit.id}" class="btn btn-cyber-outline btn-sm" title="View Full Report">
              <i class="bi bi-file-earmark-text me-1"></i>View
            </a>
            <a href="${pdfUrl}" target="_blank" class="btn btn-cyber-outline btn-sm" title="Download Report PDF">
              <i class="bi bi-file-earmark-pdf me-1"></i>PDF
            </a>
            <button class="btn btn-cyber-danger btn-sm delete-audit-btn" data-id="${audit.id}" title="Delete Report">
              <i class="bi bi-trash"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  // Attach delete handlers
  tbody.querySelectorAll('.delete-audit-btn').forEach(btn => {
    btn.addEventListener('click', () => handleDeleteAudit(btn.dataset.id));
  });

  updatePagination(filteredAudits.length);
}

function updatePagination(totalCount) {
  const pagePrev = document.getElementById('page-prev');
  const pageNext = document.getElementById('page-next');
  const pagInfo = document.getElementById('pagination-info');

  const totalPages = Math.ceil(totalCount / itemsPerPage) || 1;

  if (currentPage > totalPages) currentPage = totalPages;

  // Pagination display text
  const start = totalCount === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1;
  const end = Math.min(currentPage * itemsPerPage, totalCount);
  pagInfo.textContent = `Showing ${start}-${end} of ${totalCount} entries`;

  // Prev / Next button states
  pagePrev.classList.toggle('disabled', currentPage === 1);
  pageNext.classList.toggle('disabled', currentPage === totalPages);

  // Render Page Numbers
  const paginationUl = document.querySelector('.pagination');
  // clear existing numbers
  paginationUl.querySelectorAll('.page-number').forEach(el => el.remove());

  const prevNode = document.getElementById('page-prev');
  for (let i = 1; i <= totalPages; i++) {
    const li = document.createElement('li');
    li.className = `page-item page-number ${i === currentPage ? 'active' : ''}`;
    li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
    li.addEventListener('click', (e) => {
      e.preventDefault();
      currentPage = i;
      renderTable();
    });
    
    // insert before next page button
    paginationUl.insertBefore(li, document.getElementById('page-next'));
  }

  // Setup previous and next click events once
  if (!pagePrev.dataset.bound) {
    pagePrev.addEventListener('click', (e) => {
      e.preventDefault();
      if (currentPage > 1) {
        currentPage--;
        renderTable();
      }
    });
    pagePrev.dataset.bound = "true";
  }

  if (!pageNext.dataset.bound) {
    pageNext.addEventListener('click', (e) => {
      e.preventDefault();
      if (currentPage < totalPages) {
        currentPage++;
        renderTable();
      }
    });
    pageNext.dataset.bound = "true";
  }
}

async function handleDeleteAudit(auditId) {
  const confirmed = await showConfirm(`Delete Audit Report #${auditId}? This action cannot be undone.`);
  if (!confirmed) return;
  try {
    await API.deleteAudit(auditId);
    showToast(`Audit Report #${auditId} deleted.`, 'success');
    await loadAudits();
  } catch (error) {
    showToast(`Failed to delete audit: ${error.message}`, 'danger');
  }
}
