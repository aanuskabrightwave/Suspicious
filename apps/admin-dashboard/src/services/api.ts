// ADMIN DASHBOARD - Antigravity
// TODO: Implement request logging to Sentry

/**
 * apps/admin-dashboard/src/services/api.ts
 */
import axios from 'axios';
import { store } from '../redux/store';

const apiClient = axios.create({
  baseURL: process.env.EXPO_PUBLIC_API_URL || 'http://localhost:3000/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const token = store.getState().auth.token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export const adminApi = {
  getStats: () => apiClient.get('/dashboard/stats'),
  getUsers: () => apiClient.get('/users'),
  getScans: (params: any) => apiClient.get('/scans', { params }),
  getAlerts: () => apiClient.get('/alerts?status=pending'),
  markAlertRead: (id: string) => apiClient.post(`/alerts/${id}/mark-read`),
  login: (data: any) => apiClient.post('/auth/login', data),
  refresh: (refreshToken: string) => apiClient.post('/auth/refresh', { refreshToken }),
};

export default apiClient;
