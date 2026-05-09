// ADMIN DASHBOARD - Antigravity
// TODO: Implement state hydration from MMKV for persistence

/**
 * apps/admin-dashboard/src/redux/store.ts
 */
import { configureStore } from '@reduxjs/toolkit';
import { setupListeners } from '@reduxjs/toolkit/query';
import authReducer from './slices/authSlice';
import dashboardReducer from './slices/dashboardSlice';
import userReducer from './slices/userSlice';
import alertReducer from './slices/alertSlice';
import { apiMiddleware } from './middleware/apiMiddleware';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    dashboard: dashboardReducer,
    users: userReducer,
    alerts: alertReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false,
    }).concat(apiMiddleware),
});

setupListeners(store.dispatch);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
