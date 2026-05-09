// ADMIN DASHBOARD - Antigravity
// TODO: Integrate with Ayush's threat clustering model for advanced visualization

/**
 * apps/admin-dashboard/src/navigation/AppNavigator.tsx
 */
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { NavigationContainer } from '@react-navigation/native';
import { useSelector } from 'react-redux';
import { RootState } from '../redux/store';
import { 
  LayoutDashboard, 
  Users, 
  ShieldAlert, 
  Bell, 
  Settings,
  LogIn
} from 'lucide-react-native';

// Screens
import LoginScreen from '../screens/auth/LoginScreen';
import ResetPasswordScreen from '../screens/auth/ResetPasswordScreen';
import DashboardScreen from '../screens/dashboard/DashboardScreen';
import UserListScreen from '../screens/users/UserListScreen';
import UserDetailScreen from '../screens/users/UserDetailScreen';
import ScanListScreen from '../screens/scans/ScanListScreen';
import ScanDetailScreen from '../screens/scans/ScanDetailScreen';
import AlertListScreen from '../screens/alerts/AlertListScreen';
import AlertDetailScreen from '../screens/alerts/AlertDetailScreen';
import AdminSettingsScreen from '../screens/settings/AdminSettingsScreen';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();

const DashboardStack = () => (
  <Stack.Navigator screenOptions={{ headerStyle: { backgroundColor: '#0f172a' }, headerTintColor: '#fff' }}>
    <Stack.Screen name="DashboardMain" component={DashboardScreen} options={{ title: 'Security Overview' }} />
  </Stack.Navigator>
);

const UserStack = () => (
  <Stack.Navigator screenOptions={{ headerStyle: { backgroundColor: '#0f172a' }, headerTintColor: '#fff' }}>
    <Stack.Screen name="UserList" component={UserListScreen} options={{ title: 'User Management' }} />
    <Stack.Screen name="UserDetail" component={UserDetailScreen} options={{ title: 'User Profile' }} />
  </Stack.Navigator>
);

const ScanStack = () => (
  <Stack.Navigator screenOptions={{ headerStyle: { backgroundColor: '#0f172a' }, headerTintColor: '#fff' }}>
    <Stack.Screen name="ScanList" component={ScanListScreen} options={{ title: 'AI Scans' }} />
    <Stack.Screen name="ScanDetail" component={ScanDetailScreen} options={{ title: 'Analysis Report' }} />
  </Stack.Navigator>
);

const AlertStack = () => (
  <Stack.Navigator screenOptions={{ headerStyle: { backgroundColor: '#0f172a' }, headerTintColor: '#fff' }}>
    <Stack.Screen name="AlertList" component={AlertListScreen} options={{ title: 'Threat Alerts' }} />
    <Stack.Screen name="AlertDetail" component={AlertDetailScreen} options={{ title: 'Threat Intelligence' }} />
  </Stack.Navigator>
);

const MainTabs = () => (
  <Tab.Navigator
    screenOptions={({ route }) => ({
      tabBarIcon: ({ color, size }) => {
        const icons = {
          Dashboard: LayoutDashboard,
          Users: Users,
          Scans: ShieldAlert,
          Alerts: Bell,
          Settings: Settings,
        };
        const Icon = icons[route.name as keyof typeof icons];
        return <Icon color={color} size={size} />;
      },
      tabBarStyle: { backgroundColor: '#0f172a', borderTopWidth: 0, height: 60, paddingBottom: 10 },
      tabBarActiveTintColor: '#38bdf8',
      tabBarInactiveTintColor: '#64748b',
      headerShown: false,
    })}
  >
    <Tab.Screen name="Dashboard" component={DashboardStack} />
    <Tab.Screen name="Users" component={UserStack} />
    <Tab.Screen name="Scans" component={ScanStack} />
    <Tab.Screen name="Alerts" component={AlertStack} />
    <Tab.Screen name="Settings" component={AdminSettingsScreen} />
  </Tab.Navigator>
);

export default function AppNavigator() {
  const { isAuthenticated } = useSelector((state: RootState) => state.auth);

  return (
    <NavigationContainer>
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        {!isAuthenticated ? (
          <>
            <Stack.Screen name="Login" component={LoginScreen} />
            <Stack.Screen name="ResetPassword" component={ResetPasswordScreen} />
          </>
        ) : (
          <Stack.Screen name="Main" component={MainTabs} />
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}
