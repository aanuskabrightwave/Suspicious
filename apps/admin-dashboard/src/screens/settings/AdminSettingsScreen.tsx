// ADMIN DASHBOARD - Antigravity
// TODO: Implement MMKV-backed persistent settings storage

/**
 * apps/admin-dashboard/src/screens/settings/AdminSettingsScreen.tsx
 */
import React, { useState } from 'react';
import { View, Text, Switch, TouchableOpacity, ScrollView } from 'react-native';
import { useDispatch, useSelector } from 'react-redux';
import { logout } from '../../redux/slices/authSlice';
import { RootState } from '../../redux/store';
import { LogOut, Shield, Bell, Database } from 'lucide-react-native';

const AdminSettingsScreen = () => {
  const [pushEnabled, setPushEnabled] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const user = useSelector((state: RootState) => state.auth.user);
  const dispatch = useDispatch();

  const handleLogout = () => {
    dispatch(logout());
  };

  return (
    <ScrollView className="flex-1 bg-slate-950 p-6 pt-16">
      <Text className="text-white text-3xl font-bold mb-8">Admin Terminal</Text>

      <View className="bg-slate-900 rounded-2xl border border-slate-800 p-6 mb-8 items-center flex-row">
        <View className="h-16 w-16 rounded-full bg-sky-500/20 items-center justify-center mr-4">
          <Text className="text-sky-400 text-2xl font-bold">{user?.name?.charAt(0)}</Text>
        </View>
        <View>
          <Text className="text-white text-xl font-bold">{user?.name}</Text>
          <Text className="text-slate-400 text-sm">{user?.role} • Security Level 4</Text>
        </View>
      </View>

      <Text className="text-slate-500 text-xs font-bold uppercase mb-4 ml-1">System Preferences</Text>
      <View className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden mb-8">
        <View className="p-4 border-b border-slate-800 flex-row justify-between items-center">
          <View className="flex-row items-center">
            <Bell color="#64748b" size={18} />
            <Text className="text-white ml-3 font-medium">Critical Push Alerts</Text>
          </View>
          <Switch value={pushEnabled} onValueChange={setPushEnabled} trackColor={{ false: '#1e293b', true: '#38bdf8' }} />
        </View>

        <View className="p-4 border-b border-slate-800 flex-row justify-between items-center">
          <View className="flex-row items-center">
            <Database color="#64748b" size={18} />
            <Text className="text-white ml-3 font-medium">Real-time Data Stream</Text>
          </View>
          <Switch value={autoRefresh} onValueChange={setAutoRefresh} trackColor={{ false: '#1e293b', true: '#38bdf8' }} />
        </View>

        <View className="p-4 flex-row justify-between items-center">
          <View className="flex-row items-center">
            <Shield color="#64748b" size={18} />
            <Text className="text-white ml-3 font-medium">Auto-Lock Terminal</Text>
          </View>
          <Switch value={true} trackColor={{ false: '#1e293b', true: '#38bdf8' }} />
        </View>
      </View>

      <TouchableOpacity 
        onPress={handleLogout}
        className="bg-rose-500/10 p-5 rounded-2xl border border-rose-500/20 flex-row justify-center items-center mb-10"
      >
        <LogOut color="#f43f5e" size={20} />
        <Text className="text-rose-500 font-bold ml-2">Terminate Session</Text>
      </TouchableOpacity>
      
      <Text className="text-center text-slate-600 text-[10px] mb-10">Cyber Shield Admin v1.4.2-stable • NODE-24-X</Text>
    </ScrollView>
  );
};

export default AdminSettingsScreen;
