// ADMIN DASHBOARD - Antigravity
// TODO: Implement alert severity threshold settings

/**
 * apps/admin-dashboard/src/redux/slices/alertSlice.ts
 */
import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { Alert } from '../../types';

interface AlertState {
  alerts: Alert[];
  unreadCount: number;
}

const initialState: AlertState = {
  alerts: [],
  unreadCount: 0,
};

const alertSlice = createSlice({
  name: 'alerts',
  initialState,
  reducers: {
    addAlert: (state, action: PayloadAction<Alert>) => {
      state.alerts.unshift(action.payload);
      state.unreadCount += 1;
    },
    setAlerts: (state, action: PayloadAction<Alert[]>) => {
      state.alerts = action.payload;
      state.unreadCount = action.payload.filter(a => !a.isRead).length;
    },
    markAlertAsRead: (state, action: PayloadAction<string>) => {
      const alert = state.alerts.find(a => a.id === action.payload);
      if (alert && !alert.isRead) {
        alert.isRead = true;
        state.unreadCount = Math.max(0, state.unreadCount - 1);
      }
    },
  },
});

export const { addAlert, setAlerts, markAlertAsRead } = alertSlice.actions;
export default alertSlice.reducer;
