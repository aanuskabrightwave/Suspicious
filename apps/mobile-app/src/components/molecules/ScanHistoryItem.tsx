// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/components/molecules/ScanHistoryItem.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';
import RiskBadge from '../atoms/RiskBadge';

export default function ScanHistoryItem({ item }: any) {
  return (
    <View className="flex-row justify-between p-4 bg-slate-900 mb-2 rounded-xl">
      <Text className="text-white flex-1 mr-2" numberOfLines={1}>{item.target}</Text>
      <RiskBadge level={item.riskLevel} />
    </View>
  );
}
