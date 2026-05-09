// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/App.tsx
 */
import React from 'react';
import { Provider } from 'react-redux';
import { store } from './redux/store';
import RootNavigator from './navigation/RootNavigator';

export default function App() {
  return (
    <Provider store={store}>
      <RootNavigator />
    </Provider>
  );
}
