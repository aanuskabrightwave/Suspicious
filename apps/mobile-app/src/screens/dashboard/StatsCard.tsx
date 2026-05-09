// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/dashboard/StatsCard.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';

export default function StatsCard({ label, value }: any) {
  return (
    <View className="bg-slate-900 p-4 rounded-2xl mb-4">
      <Text className="text-slate-400 text-xs uppercase">{label}</Text>
      <Text className="text-white text-xl font-bold">{value}</Text>
    </View>
  );
}
