import { configureStore } from '@reduxjs/toolkit';
import threatReducer from './threatSlice';

export const store = configureStore({
  reducer: {
    threats: threatReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
