// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/settings/SecuritySettingsScreen.tsx
 */
import React from 'react';
import { View, Text, TouchableOpacity } from 'react-native';
import { useDispatch } from 'react-redux';
import { logout } from '../../redux/slices/authSlice';

export default function SecuritySettingsScreen() {
  const dispatch = useDispatch();
  return (
    <View className="flex-1 bg-slate-950 p-6">
      <TouchableOpacity className="bg-rose-500/10 p-4 rounded-xl" onPress={() => dispatch(logout())}>
        <Text className="text-rose-500 font-bold text-center">Logout</Text>
      </TouchableOpacity>
    </View>
  );
}
