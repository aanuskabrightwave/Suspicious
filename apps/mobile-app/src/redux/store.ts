// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/redux/store.ts
 */
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import scanReducer from './slices/scanSlice';
import alertReducer from './slices/alertSlice';
import { apiMiddleware } from './middleware/apiMiddleware';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    scans: scanReducer,
    alerts: alertReducer,
  },
  middleware: (getDefault) => getDefault().concat(apiMiddleware),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;