// ADMIN DASHBOARD - Antigravity
// TODO: Implement swipe actions for quick archiving

/**
 * apps/admin-dashboard/src/components/molecules/ScanHistoryItem.tsx
 */
import React from 'react';
import { View, Text, TouchableOpacity } from 'react-native';
import { Globe, Link2, FileText } from 'lucide-react-native';
import RiskBadge from '../atoms/RiskBadge';

const ScanHistoryItem = ({ item, onPress }: any) => {
  const Icon = item.type === 'URL' ? Link2 : item.type === 'File' ? FileText : Globe;

  return (
    <TouchableOpacity 
      onPress={onPress}
      className="bg-slate-900/60 p-4 rounded-2xl mb-4 border border-slate-800/80 flex-row items-center"
    >
      <View className={`p-3 rounded-xl mr-4 ${item.riskScore > 70 ? 'bg-rose-500/10' : 'bg-sky-500/10'}`}>
        <Icon color={item.riskScore > 70 ? '#f43f5e' : '#38bdf8'} size={24} />
      </View>
      <View className="flex-1">
        <Text className="text-white font-bold text-sm" numberOfLines={1}>{item.target}</Text>
        <Text className="text-slate-500 text-xs mt-1">{new Date(item.createdAt).toLocaleTimeString()} • {item.type}</Text>
      </View>
      <View className="items-end">
        <RiskBadge level={item.riskLevel} />
        <Text className="text-slate-600 text-[10px] mt-2 font-mono">ID: {item.id.slice(0, 8)}</Text>
      </View>
    </TouchableOpacity>
  );
};

export default ScanHistoryItem;
