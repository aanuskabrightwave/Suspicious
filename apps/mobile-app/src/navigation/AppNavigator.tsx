import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';
import DashboardScreen from '../screens/DashboardScreen';
import QRScannerScreen from '../screens/QRScannerScreen';
// import LoginScreen from '../screens/LoginScreen';

const Stack = createStackNavigator();

// ======================================
// ANUSKA WORK AREA
// Build UI navigation logic here
// Add authentication guard (LoginScreen) if token is missing
// Connect new screens (e.g., Settings, ThreatDetails)
// ======================================

export default function AppNavigator() {
  return (
    <Stack.Navigator initialRouteName="Dashboard">
      {/* <Stack.Screen name="Login" component={LoginScreen} options={{ headerShown: false }} /> */}
      <Stack.Screen 
        name="Dashboard" 
        component={DashboardScreen} 
        options={{ title: 'Cyber Shield Dashboard' }} 
      />
      <Stack.Screen 
        name="QRScanner" 
        component={QRScannerScreen} 
        options={{ title: 'Scan QR Code' }} 
      />
    </Stack.Navigator>
  );
}
