// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/redux/slices/authSlice.ts
 */
import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export const authSlice = createSlice({
  name: 'auth',
  initialState: { user: null, token: null, refreshToken: null, isAuthenticated: false },
  reducers: {
    setCredentials: (state, action) => {
      Object.assign(state, action.payload, { isAuthenticated: true });
    },
    logout: (state) => {
      state.user = null; state.token = null; state.isAuthenticated = false;
    }
  }
});
export const { setCredentials, logout } = authSlice.actions;
export default authSlice.reducer;