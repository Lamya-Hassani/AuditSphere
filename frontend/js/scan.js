import { renderNavbar, showToast } from './app.js?v=1.0.3';
import { API } from './api.js?v=1.0.3';

document.addEventListener('DOMContentLoaded', () => {
  renderNavbar('scan');

  const urlParams = new URLSearchParams(window.location.search);
  const initialTarget = urlParams.get('target');
  const autoScan = urlParams.get('auto') === 'true';

  const targetInput = document.getElementById('target-input');
  const scanForm = document.getElementById('scan-form');

  if (initialTarget && targetInput) {
    targetInput.value = decodeURIComponent(initialTarget);

    if (autoScan) {
      setTimeout(() => {
        scanForm.dispatchEvent(new Event('submit'));
      }, 500);
    }
  }

  scanForm.addEventListener('submit', handleScanSubmit);

  document.getElementById('success-scan-another')?.addEventListener('click', () => {
    document.getElementById('scan-success-card').classList.add('d-none');
    document.getElementById('scan-form-card').classList.remove('d-none');
    if (targetInput) {
      targetInput.value = '';
      targetInput.focus();
    }
  });
});

// Progress messages per mode
const MODE_MESSAGES = {
  full: [
    'Initializing Kali VM audit engine...',
    'Running ICMP/ARP host discovery sweep...',
    'Executing deep Nmap scan (-A) on active hosts...',
    'Correlating services with vulnerability rule database...',
    'Calculating risk scores and security posture indices...',
  ],
  discovery: [
    'Initializing Kali VM audit engine...',
    'Running ICMP/ARP ping sweep (nmap -sn)...',
    'Waiting for host responses...',
    'Parsing discovered hosts from XML output...',
  ],
  ports: [
    'Initializing Kali VM audit engine...',
    'Running ICMP/ARP host discovery sweep...',
    'Executing port sweep (nmap -sV --open -T4)...',
    'Parsing open ports and service banners...',
  ],
};

async function handleScanSubmit(e) {
  e.preventDefault();

  const targetInput = document.getElementById('target-input');
  const target = targetInput.value.trim();
  if (!target) return;

  const modeInput = document.querySelector('input[name="scan-mode"]:checked');
  const mode = modeInput ? modeInput.value : 'full';

  const formCard       = document.getElementById('scan-form-card');
  const scanningOverlay = document.getElementById('scanning-overlay');
  const successCard    = document.getElementById('scan-success-card');
  const errorAlert     = document.getElementById('scan-error-alert');
  const statusText     = document.getElementById('scanning-status-text');
  const scanTitle      = document.getElementById('scanning-title');

  // Update loading title to reflect mode
  const modeTitles = {
    full:      'Executing Full Vulnerability Audit...',
    discovery: 'Executing Host Discovery Scan...',
    ports:     'Executing Port Sweep Scan...',
  };
  if (scanTitle) scanTitle.textContent = modeTitles[mode] || 'Executing Audit Scan...';

  if (formCard)       formCard.classList.add('d-none');
  if (successCard)    successCard.classList.add('d-none');
  if (errorAlert)     errorAlert.classList.add('d-none');
  if (scanningOverlay) scanningOverlay.classList.remove('d-none');

  const messages = MODE_MESSAGES[mode] || MODE_MESSAGES.full;
  let msgIndex = 0;
  if (statusText) statusText.textContent = messages[0];

  const interval = setInterval(() => {
    msgIndex = (msgIndex + 1) % messages.length;
    if (statusText) statusText.textContent = messages[msgIndex];
  }, 4000);

  try {
    const audit = await API.runAudit(target, mode);
    clearInterval(interval);

    if (scanningOverlay) scanningOverlay.classList.add('d-none');

    // Populate success card based on mode
    populateSuccessCard(audit, mode, target);

    showToast(`Scan completed! Mode: ${mode}`, 'success');
    if (successCard) successCard.classList.remove('d-none');

  } catch (error) {
    clearInterval(interval);
    if (scanningOverlay) scanningOverlay.classList.add('d-none');
    if (formCard) formCard.classList.remove('d-none');

    const errorMessageEl = document.getElementById('scan-error-message');
    if (errorMessageEl) errorMessageEl.textContent = error.message;
    if (errorAlert) errorAlert.classList.remove('d-none');

    showToast(`Scan failed: ${error.message}`, 'danger');
  }
}

function populateSuccessCard(audit, mode, target) {
  const stats = audit.statistics || {};
  const deviceCount = stats.devices ?? (audit.devices?.length ?? 0);

  document.getElementById('success-target-text').textContent =
    `Scan completed for target: ${audit.target || target}`;

  // Slot 1 — Mode label
  document.getElementById('success-mode-label').textContent = {
    full:      'Full Audit',
    discovery: 'Host Discovery',
    ports:     'Port Sweep',
  }[mode] || mode;

  // Slot 2 — Discovered Hosts (always)
  document.getElementById('success-hosts-text').textContent = deviceCount;

  // Slot 3 — varies per mode
  const scoreBox   = document.getElementById('success-score-box');
  const scoreText  = document.getElementById('success-score-text');
  const vulnsBox   = document.getElementById('success-vulns-box');
  const vulnsText  = document.getElementById('success-vulns-text');
  const portsBox   = document.getElementById('success-ports-box');
  const portsLabel = document.getElementById('success-ports-label');
  const portsText  = document.getElementById('success-ports-text');

  // Hide all optional boxes first
  if (scoreBox) scoreBox.classList.add('d-none');
  if (vulnsBox) vulnsBox.classList.add('d-none');
  if (portsBox) portsBox.classList.add('d-none');

  if (mode === 'full') {
    if (scoreBox)  scoreBox.classList.remove('d-none');
    if (scoreText) scoreText.textContent = `${audit.laboratory_security_score ?? 100}/100`;
    if (vulnsBox)  vulnsBox.classList.remove('d-none');
    if (vulnsText) vulnsText.textContent = (stats.critical ?? 0) + (stats.high ?? 0);
  } else if (mode === 'discovery') {
    // Nothing extra — only host count matters
  } else if (mode === 'ports') {
    if (portsBox)   portsBox.classList.remove('d-none');
    const totalPorts = (audit.devices || []).reduce((sum, d) => sum + (d.ports?.length ?? 0), 0);
    if (portsText)  portsText.textContent = totalPorts;
  }

  // Bind action buttons
  const viewReportBtn = document.getElementById('success-view-report');
  if (viewReportBtn) viewReportBtn.href = `audit-details.html?id=${audit.id}`;

  const downloadPdfBtn = document.getElementById('success-download-pdf');
  if (downloadPdfBtn) {
    downloadPdfBtn.href   = API.downloadAuditPdfUrl(audit.id);
    downloadPdfBtn.target = '_blank';
  }
}
