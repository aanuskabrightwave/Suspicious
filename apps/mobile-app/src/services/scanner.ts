// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/services/scanner.ts
 */
import { Camera } from 'react-native-vision-camera';

export const requestCameraPermission = async () => {
  const status = await Camera.requestCameraPermission();
  return status === 'authorized';
};
