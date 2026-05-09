// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/components/atoms/RiskBadge.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';

export default function RiskBadge({ level }: any) {
  const colors = { high: 'bg-rose-500', medium: 'bg-amber-500', safe: 'bg-emerald-500' };
  return (
    <View className={`${(colors as any)[level] || 'bg-slate-500'} px-2 py-1 rounded`}>
      <Text className="text-white text-[10px] font-bold uppercase">{level}</Text>
    </View>
  );
}
