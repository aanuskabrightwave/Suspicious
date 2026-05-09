// ADMIN DASHBOARD - Antigravity
// TODO: Implement advanced backoff retry strategy for flaky connections

/**
 * apps/admin-dashboard/src/redux/middleware/apiMiddleware.ts
 */
import axios from 'axios';
import { store } from '../store';
import { logout, updateToken } from '../slices/authSlice';

const api = axios.create({
  baseURL: process.env.EXPO_PUBLIC_API_URL,
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  const state = store.getState();
  const token = state.auth.token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshToken = store.getState().auth.refreshToken;
        const response = await axios.post(`${process.env.EXPO_PUBLIC_API_URL}/auth/refresh`, {
          refreshToken,
        });
        const { token } = response.data;
        store.dispatch(updateToken(token));
        originalRequest.headers.Authorization = `Bearer ${token}`;
        return api(originalRequest);
      } catch (err) {
        store.dispatch(logout());
        return Promise.reject(err);
      }
    }
    return Promise.reject(error);
  }
);

export const apiMiddleware = () => (next: any) => (action: any) => {
  return next(action);
};

export default api;
