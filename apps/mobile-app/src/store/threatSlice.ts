import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// ======================================
// ANUSKA WORK AREA
// Manage application state here
// Add async thunks for fetching threats from API
// ======================================

interface Threat {
  id: string;
  type: 'PHISHING' | 'MALWARE' | 'SCAM';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  timestamp: string;
}

interface ThreatState {
  threats: Threat[];
  loading: boolean;
  error: string | null;
}

const initialState: ThreatState = {
  threats: [],
  loading: false,
  error: null,
};

const threatSlice = createSlice({
  name: 'threats',
  initialState,
  reducers: {
    addThreat(state, action: PayloadAction<Threat>) {
      state.threats.push(action.payload);
    },
    setLoading(state, action: PayloadAction<boolean>) {
      state.loading = action.payload;
    },
    // TODO: Add more reducers (clearThreats, resolveThreat)
  },
});

export const { addThreat, setLoading } = threatSlice.actions;
export default threatSlice.reducer;
