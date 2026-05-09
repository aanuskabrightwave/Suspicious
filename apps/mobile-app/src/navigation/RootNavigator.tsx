// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/navigation/RootNavigator.tsx
 */
import React, { useEffect, useState } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../redux/store';
import { setCredentials } from '../redux/slices/authSlice';
import { checkRootStatus, initializeSSLPinning } from '../services/security';
import { storage, StorageKeys } from '../utils/storage';
import AppNavigator from './AppNavigator';
import LoginScreen from '../screens/auth/LoginScreen';
import RegisterScreen from '../screens/auth/RegisterScreen';
import LoadingIndicator from '../components/atoms/LoadingIndicator';
import { Alert } from 'react-native';

const Stack = createStackNavigator();

export default function RootNavigator() {
  const { isAuthenticated } = useSelector((state: RootState) => state.auth);
  const [isSecurityCheckPassed, setIsSecurityCheckPassed] = useState(false);
  const dispatch = useDispatch();

  useEffect(() => {
    const init = async () => {
      const isRooted = await checkRootStatus();
      if (isRooted) {
        Alert.alert('Security Alert', 'Rooted device detected. App execution restricted.');
      }
      await initializeSSLPinning();
      
      const token = storage.getString(StorageKeys.AUTH_TOKEN);
      const userStr = storage.getString(StorageKeys.USER_DATA);
      if (token && userStr) {
        dispatch(setCredentials({ 
          token, 
          user: JSON.parse(userStr), 
          refreshToken: storage.getString(StorageKeys.REFRESH_TOKEN) || '' 
        }));
      }
      setIsSecurityCheckPassed(true);
    };
    init();
  }, [dispatch]);

  if (!isSecurityCheckPassed) return <LoadingIndicator label="Securing..." />;

  return (
    <NavigationContainer>
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        {!isAuthenticated ? (
          <>
            <Stack.Screen name="Login" component={LoginScreen} />
            <Stack.Screen name="Register" component={RegisterScreen} />
          </>
        ) : (
          <Stack.Screen name="Main" component={AppNavigator} />
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}