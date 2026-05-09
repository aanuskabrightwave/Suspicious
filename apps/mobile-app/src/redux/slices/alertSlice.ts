// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/redux/slices/alertSlice.ts
 */
import { createSlice } from '@reduxjs/toolkit';

export const alertSlice = createSlice({
  name: 'alerts',
  initialState: { list: [], unread: 0 },
  reducers: {
    addAlert: (state, action) => { state.list.unshift(action.payload); state.unread++; }
  }
});
export const { addAlert } = alertSlice.actions;
export default alertSlice.reducer;