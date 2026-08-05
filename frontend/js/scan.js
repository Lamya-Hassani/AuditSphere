import { renderNavbar, showToast } from './app.js';
import { API } from './api.js';

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
});

async function handleScanSubmit(e) {
  e.preventDefault();

  const targetInput = document.getElementById('target-input');
  const target = targetInput.value.trim();
  if (!target) return;

  const formCard = document.querySelector('.cyber-card');
  const scanningOverlay = document.getElementById('scanning-overlay');
  const errorAlert = document.getElementById('scan-error-alert');
  const statusText = document.getElementById('scanning-status-text');

  // Hide form & error, show radar overlay
  if (formCard) formCard.classList.add('d-none');
  if (errorAlert) errorAlert.classList.add('d-none');
  if (scanningOverlay) scanningOverlay.classList.remove('d-none');

  // Cycle status messages for visual feedback
  const messages = [
    `Initializing scan engine for target ${target}...`,
    "Sending ICMP & SYN discovery probes...",
    "Inspecting open ports and banner versions...",
    "Running vulnerability risk scoring engine...",
    "Generating audit report & persisting inventory..."
  ];

  let msgIndex = 0;
  const interval = setInterval(() => {
    msgIndex = (msgIndex + 1) % messages.length;
    if (statusText) statusText.textContent = messages[msgIndex];
  }, 3500);

  try {
    const audit = await API.runAudit(target);
    clearInterval(interval);
    showToast(`Audit completed successfully! Score: ${audit.laboratory_security_score}/100`, 'success');

    setTimeout(() => {
      window.location.href = `audit-details.html?id=${audit.id}`;
    }, 1000);

  } catch (error) {
    clearInterval(interval);
    if (scanningOverlay) scanningOverlay.classList.add('d-none');
    if (formCard) formCard.classList.remove('d-none');

    const errorMessageEl = document.getElementById('scan-error-message');
    if (errorMessageEl) errorMessageEl.textContent = error.message;
    if (errorAlert) errorAlert.classList.remove('d-none');

    showToast(`Scan execution failed: ${error.message}`, 'danger');
  }
}
