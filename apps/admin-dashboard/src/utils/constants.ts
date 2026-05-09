// ADMIN DASHBOARD - Antigravity
/**
 * apps/admin-dashboard/src/utils/constants.ts
 */
export const ADMIN_ROLES = ['superadmin', 'analyst', 'support'];

export const SCAN_TYPES = ['URL', 'File', 'Image', 'IP'];

export const RISK_LEVELS = {
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

export const API_ENDPOINTS = {
  STATS: '/dashboard/stats',
  USERS: '/users',
  SCANS: '/scans',
  ALERTS: '/alerts',
  AUTH_ME: '/auth/me',
  AUTH_REFRESH: '/auth/refresh',
};
