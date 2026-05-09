// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/navigation/AppNavigator.tsx
 */
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { LayoutDashboard, Scan, History, Settings } from 'lucide-react-native';
import DashboardScreen from '../screens/dashboard/DashboardScreen';
import URLScannerScreen from '../screens/scanner/URLScannerScreen';
import SecuritySettingsScreen from '../screens/settings/SecuritySettingsScreen';

const Tab = createBottomTabNavigator();

export default function AppNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ color, size }) => {
          const icons = { Dashboard: LayoutDashboard, Scanner: Scan, History: History, Settings: Settings };
          const Icon = icons[route.name as keyof typeof icons];
          return <Icon color={color} size={size} />;
        },
        tabBarActiveTintColor: '#0ea5e9',
        tabBarInactiveTintColor: '#64748b',
        tabBarStyle: { backgroundColor: '#0f172a', borderTopWidth: 0 },
        headerStyle: { backgroundColor: '#0f172a' },
        headerTintColor: '#fff',
      })}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} />
      <Tab.Screen name="Scanner" component={URLScannerScreen} options={{ title: 'AI Scan' }} />
      <Tab.Screen name="Settings" component={SecuritySettingsScreen} />
    </Tab.Navigator>
  );
}
