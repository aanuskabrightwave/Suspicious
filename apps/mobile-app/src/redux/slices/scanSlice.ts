// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/redux/slices/scanSlice.ts
 */
import { createSlice } from '@reduxjs/toolkit';

export const scanSlice = createSlice({
  name: 'scans',
  initialState: { history: [], isScanning: false },
  reducers: {
    addScan: (state, action) => { state.history.unshift(action.payload); },
    setScanning: (state, action) => { state.isScanning = action.payload; }
  }
});
export const { addScan, setScanning } = scanSlice.actions;
export default scanSlice.reducer;