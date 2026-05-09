// ADMIN DASHBOARD - Antigravity
// TODO: Add tooltip support for risk level explanations

/**
 * apps/admin-dashboard/src/components/atoms/RiskBadge.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';

interface Props {
  level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

const RiskBadge = ({ level }: Props) => {
  const configs = {
    safe: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
    low: { color: 'text-sky-400', bg: 'bg-sky-500/10', border: 'border-sky-500/20' },
    medium: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
    high: { color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20' },
    critical: { color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
  };

  const config = configs[level] || configs.safe;

  return (
    <View className={`${config.bg} ${config.border} border px-2 py-0.5 rounded-md`}>
      <Text className={`${config.color} text-[10px] font-black uppercase tracking-tighter`}>{level}</Text>
    </View>
  );
};

export default RiskBadge;
