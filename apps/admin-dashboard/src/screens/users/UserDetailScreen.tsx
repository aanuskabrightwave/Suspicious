// ADMIN DASHBOARD - Antigravity
// TODO: Add activity log visualization for specific users

/**
 * apps/admin-dashboard/src/screens/users/UserDetailScreen.tsx
 */
import React from 'react';
import { View, Text, ScrollView, TouchableOpacity } from 'react-native';
import { Shield, Mail, Calendar, Lock, Trash2 } from 'lucide-react-native';
import RiskBadge from '../../components/atoms/RiskBadge';

const UserDetailScreen = ({ route }: any) => {
  const { user } = route.params;

  return (
    <ScrollView className="flex-1 bg-slate-950 p-6">
      <View className="items-center mb-8">
        <View className="h-24 w-24 rounded-3xl bg-sky-500/10 items-center justify-center border border-sky-500/30 mb-4">
          <Text className="text-sky-400 text-3xl font-bold">{user.name.charAt(0)}</Text>
        </View>
        <Text className="text-white text-2xl font-bold">{user.name}</Text>
        <Text className="text-slate-400 text-sm">{user.role}</Text>
      </View>

      <View className="bg-slate-900/50 rounded-2xl border border-slate-800 overflow-hidden">
        <View className="p-4 border-b border-slate-800 flex-row items-center">
          <Mail color="#64748b" size={18} />
          <View className="ml-4">
            <Text className="text-slate-500 text-xs uppercase font-bold">Email</Text>
            <Text className="text-white font-medium">{user.email}</Text>
          </View>
        </View>

        <View className="p-4 border-b border-slate-800 flex-row items-center">
          <Calendar color="#64748b" size={18} />
          <View className="ml-4">
            <Text className="text-slate-500 text-xs uppercase font-bold">Joined</Text>
            <Text className="text-white font-medium">{new Date(user.createdAt).toLocaleDateString()}</Text>
          </View>
        </View>

        <View className="p-4 flex-row items-center">
          <Shield color="#64748b" size={18} />
          <View className="ml-4">
            <Text className="text-slate-500 text-xs uppercase font-bold">Risk Status</Text>
            <RiskBadge level={user.riskLevel || 'safe'} />
          </View>
        </View>
      </View>

      <View className="mt-8 space-y-4">
        <TouchableOpacity className="flex-row items-center bg-slate-900 p-4 rounded-xl border border-slate-800">
          <Lock color="#38bdf8" size={18} />
          <Text className="text-white ml-3 font-semibold">Force Password Reset</Text>
        </TouchableOpacity>

        {user.role !== 'superadmin' && (
          <TouchableOpacity className="flex-row items-center bg-rose-500/10 p-4 rounded-xl border border-rose-500/20">
            <Trash2 color="#f43f5e" size={18} />
            <Text className="text-rose-500 ml-3 font-semibold">Suspend Account</Text>
          </TouchableOpacity>
        )}
      </View>
    </ScrollView>
  );
};

export default UserDetailScreen;
