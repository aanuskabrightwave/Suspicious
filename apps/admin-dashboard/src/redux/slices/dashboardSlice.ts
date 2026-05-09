// ADMIN DASHBOARD - Antigravity
// TODO: Add real-time KPI smoothing using Reanimated

/**
 * apps/admin-dashboard/src/redux/slices/dashboardSlice.ts
 */
import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface DashboardStats {
  totalScans: number;
  highRiskPercentage: number;
  activeThreats: number;
  systemHealth: number;
}

interface DashboardState {
  stats: DashboardStats;
  lastUpdated: string | null;
}

const initialState: DashboardState = {
  stats: {
    totalScans: 0,
    highRiskPercentage: 0,
    activeThreats: 0,
    systemHealth: 0,
  },
  lastUpdated: null,
};

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    setDashboardStats: (state, action: PayloadAction<DashboardStats>) => {
      state.stats = action.payload;
      state.lastUpdated = new Date().toISOString();
    },
  },
});

export const { setDashboardStats } = dashboardSlice.actions;
export default dashboardSlice.reducer;
