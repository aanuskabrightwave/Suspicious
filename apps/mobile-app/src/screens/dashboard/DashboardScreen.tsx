// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/dashboard/DashboardScreen.tsx
 */
import React from 'react';
import { ScrollView, View, Text } from 'react-native';
import SecurityDashboard from '../../components/organisms/SecurityDashboard';

export default function DashboardScreen() {
  return (
    <ScrollView className="flex-1 bg-slate-950">
      <View className="p-4">
        <Text className="text-white text-2xl font-bold mb-4">Security Overview</Text>
        <SecurityDashboard />
      </View>
    </ScrollView>
  );
}