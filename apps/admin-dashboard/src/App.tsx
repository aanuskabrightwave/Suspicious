// ADMIN DASHBOARD - Antigravity
// TODO: Wrap in Sentry error boundary for production crash logging

/**
 * apps/admin-dashboard/src/App.tsx
 */
import React from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { Provider } from 'react-redux';
import { store } from './redux/store';
import AppNavigator from './navigation/AppNavigator';

export default function App() {
  return (
    <Provider store={store}>
      <SafeAreaProvider>
        <StatusBar style="light" />
        <AppNavigator />
      </SafeAreaProvider>
    </Provider>
  );
}
