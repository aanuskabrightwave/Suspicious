// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/services/api.ts
 */
import client from '../redux/middleware/apiMiddleware';

export const api = {
  login: (d: any) => client.post('/auth/login', d),
  scan: (u: string) => client.post('/scan/url', { url: u }),
  stats: () => client.get('/dashboard/stats')
};
