/**
 * Cybersecurity Audit Platform - API Client
 * Connects to Django REST Framework backend
 */

const API_BASE_URL = 'http://localhost:8000/api';

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...(options.headers || {})
  };

  const config = {
    ...options,
    headers,
    credentials: 'include' // include session cookies for auth
  };

  try {
    const response = await fetch(url, config);

    // Handle 204 No Content
    if (response.status === 204) {
      return { success: true };
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = data.error || data.detail || `Request failed with status ${response.status}`;
      throw new Error(errorMessage);
    }

    return data;
  } catch (error) {
    console.error(`API Error on [${options.method || 'GET'}] ${endpoint}:`, error);
    throw error;
  }
}

export const API = {
  // Accounts Auth
  login: (username, password) => apiRequest('/accounts/login/', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  }),
  logout: () => apiRequest('/accounts/logout/', { method: 'POST' }),
  getCurrentUser: () => apiRequest('/accounts/me/'),

  // Dashboard
  getDashboardSummary: () => apiRequest('/dashboard/'),

  // Inventory
  getInventoryDevices: (search = '', status = '') => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status) params.append('status', status);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    return apiRequest(`/inventory/devices/${queryString}`);
  },

  getDeviceDetail: (id) => apiRequest(`/inventory/devices/${id}/`),
  deleteDevice: (id) => apiRequest(`/inventory/devices/${id}/`, { method: 'DELETE' }),

  // Audits
  getAudits: () => apiRequest('/audits/'),
  getAuditDetail: (id) => apiRequest(`/audits/${id}/`),
  deleteAudit: (id) => apiRequest(`/audits/${id}/`, { method: 'DELETE' }),
  runAudit: (target) => apiRequest('/audits/scan/', {
    method: 'POST',
    body: JSON.stringify({ target })
  }),
  rescanAudit: (id) => apiRequest(`/audits/${id}/rescan/`, { method: 'POST' })
};
