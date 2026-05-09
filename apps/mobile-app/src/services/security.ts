// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/services/security.ts
 */
import { isRooted } from 'react-native-root-detection';
import { initializeSslPinning } from 'react-native-ssl-pinning';

export const checkRootStatus = async () => {
  try { return await isRooted(); } catch { return false; }
};

export const initializeSSLPinning = async () => {
  try {
    await initializeSslPinning({
      'cybershield.ai': { publicKeyHashes: ['sha256/hash123...'] }
    });
  } catch {}
};
