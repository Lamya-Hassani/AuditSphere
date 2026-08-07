/**
 * Cybersecurity Audit Platform - API Client
 * Connects to Django REST Framework backend with SimpleJWT Auth
 */

const API_BASE_URL = 'http://localhost:8000/api';

export function getAccessToken() {
  return localStorage.getItem('access_token') || sessionStorage.getItem('access_token');
}

export function getRefreshToken() {
  return localStorage.getItem('refresh_token') || sessionStorage.getItem('refresh_token');
}

export function setTokens(access, refresh, rememberMe = true) {
  const storage = rememberMe ? localStorage : sessionStorage;
  storage.setItem('access_token', access);
  if (refresh) {
    storage.setItem('refresh_token', refresh);
  }
}

export function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('refresh_token');
  localStorage.removeItem('cyber_user');
  sessionStorage.removeItem('cyber_user');
}

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const token = getAccessToken();

  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(options.headers || {})
  };

  const config = {
    ...options,
    headers
  };

  try {
    let response = await fetch(url, config);

    // If 401 Unauthorized, try to refresh access token if refresh_token exists
    if (response.status === 401 && !endpoint.includes('/accounts/login/')) {
      const refresh = getRefreshToken();
      if (refresh) {
        try {
          const refreshRes = await fetch(`${API_BASE_URL}/accounts/token/refresh/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh })
          });
          if (refreshRes.ok) {
            const refreshData = await refreshRes.json();
            const remember = !!localStorage.getItem('refresh_token');
            setTokens(refreshData.access, refreshData.refresh || refresh, remember);
            
            // Retry original request with new token
            headers['Authorization'] = `Bearer ${refreshData.access}`;
            response = await fetch(url, { ...config, headers });
          } else {
            clearTokens();
            if (!window.location.pathname.endsWith('login.html')) {
              window.location.href = 'login.html';
            }
          }
        } catch (e) {
          clearTokens();
          if (!window.location.pathname.endsWith('login.html')) {
            window.location.href = 'login.html';
          }
        }
      } else {
        clearTokens();
        if (!window.location.pathname.endsWith('login.html')) {
          window.location.href = 'login.html';
        }
      }
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return { success: true };
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = data.error || data.detail || (typeof data === 'object' ? JSON.stringify(data) : `Request failed with status ${response.status}`);
      const err = new Error(errorMessage);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  } catch (error) {
    console.error(`API Error on [${options.method || 'GET'}] ${endpoint}:`, error);
    throw error;
  }
}

export const API = {
  // Token helper exports on API object
  setTokens,
  getAccessToken,
  getRefreshToken,
  clearTokens,

  // Authentication Endpoints
  login: (username, password) => apiRequest('/accounts/login/', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  }),
  logout: () => {
    const refresh = getRefreshToken();
    return apiRequest('/accounts/logout/', {
      method: 'POST',
      body: JSON.stringify({ refresh })
    }).finally(() => {
      clearTokens();
    });
  },
  refreshToken: (refresh) => apiRequest('/accounts/token/refresh/', {
    method: 'POST',
    body: JSON.stringify({ refresh })
  }),
  getCurrentUser: () => apiRequest('/accounts/me/'),

  // User CRUD Endpoints (Administrators / Super Admins only)
  getUsers: () => apiRequest('/accounts/users/'),
  getUserDetail: (id) => apiRequest(`/accounts/users/${id}/`),
  createUser: (userData) => apiRequest('/accounts/users/', {
    method: 'POST',
    body: JSON.stringify(userData)
  }),
  updateUser: (id, userData) => apiRequest(`/accounts/users/${id}/`, {
    method: 'PUT',
    body: JSON.stringify(userData)
  }),
  deleteUser: (id) => apiRequest(`/accounts/users/${id}/`, { method: 'DELETE' }),

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
  runAudit: (target, mode = 'full') => apiRequest('/audits/scan/', {
    method: 'POST',
    body: JSON.stringify({ target, mode })
  }),
  rescanAudit: (id) => apiRequest(`/audits/${id}/rescan/`, { method: 'POST' }),
  downloadAuditPdfUrl: (id) => {
    const token = getAccessToken();
    return `${API_BASE_URL}/audits/${id}/pdf/${token ? `?token=${encodeURIComponent(token)}` : ''}`;
  }
};
