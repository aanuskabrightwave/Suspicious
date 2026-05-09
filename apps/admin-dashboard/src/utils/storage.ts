// ADMIN DASHBOARD - Antigravity
// TODO: Add AES-256 encryption for sensitive local storage

/**
 * apps/admin-dashboard/src/utils/storage.ts
 */
import { Platform } from 'react-native';

// Fallback for Web since MMKV uses JSI and crashes on Web
const isWeb = Platform.OS === 'web';

let storage: any = null;
if (!isWeb) {
  const { MMKV } = require('react-native-mmkv');
  storage = new MMKV({
    id: 'cybershield-admin-storage',
    encryptionKey: 'cyber-shield-admin-secure-key-123',
  });
}

export const StorageKeys = {
  THEME: 'admin_theme',
  TIMEZONE: 'admin_timezone',
  LAST_SEEN_ALERT_ID: 'last_seen_alert_id',
  AUTO_REFRESH_INTERVAL: 'auto_refresh_interval',
};

export const getStorageItem = (key: string): string | undefined | null => {
  if (isWeb) return localStorage.getItem(key);
  return storage?.getString(key);
};

export const setStorageItem = (key: string, value: string) => {
  if (isWeb) {
    localStorage.setItem(key, value);
    return;
  }
  storage?.set(key, value);
};

export const removeStorageItem = (key: string) => {
  if (isWeb) {
    localStorage.removeItem(key);
    return;
  }
  storage?.delete(key);
};
