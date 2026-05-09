// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/utils/storage.ts
 */
import { MMKV } from 'react-native-mmkv';

export const storage = new MMKV();
export const StorageKeys = { AUTH_TOKEN: 'token', REFRESH_TOKEN: 'refresh', USER_DATA: 'user' };
export const reduxStorage = {
  setItem: (k: string, v: string) => storage.set(k, v),
  getItem: (k: string) => storage.getString(k) || null,
  removeItem: (k: string) => storage.delete(k),
};
