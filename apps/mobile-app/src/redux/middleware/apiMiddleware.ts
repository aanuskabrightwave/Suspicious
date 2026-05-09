// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/redux/middleware/apiMiddleware.ts
 */
import axios from 'axios';
import { store } from '../store';
import { logout } from '../slices/authSlice';

const client = axios.create({ baseURL: process.env.EXPO_PUBLIC_API_URL });

client.interceptors.request.use(config => {
  const token = store.getState().auth.token;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

client.interceptors.response.use(r => r, async e => {
  if (e.response?.status === 401) store.dispatch(logout());
  return Promise.reject(e);
});

export const apiMiddleware = () => (n: any) => (a: any) => n(a);
export default client;
