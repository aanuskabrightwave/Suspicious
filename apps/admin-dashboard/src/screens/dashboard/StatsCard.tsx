// ADMIN DASHBOARD - Antigravity
// TODO: Add micro-animations using Moti or Reanimated

/**
 * apps/admin-dashboard/src/screens/dashboard/StatsCard.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';
import { Shield, AlertTriangle, Activity, Cpu } from 'lucide-react-native';

interface Props {
  label: string;
  value: string;
  trend: string;
  icon: 'shield' | 'alert' | 'activity' | 'cpu';
  color: 'sky' | 'rose' | 'amber' | 'emerald';
}

const StatsCard = ({ label, value, trend, icon, color }: Props) => {
  const colorMap = {
    sky: { bg: 'bg-sky-500/10', text: 'text-sky-500', border: 'border-sky-500/20' },
    rose: { bg: 'bg-rose-500/10', text: 'text-rose-500', border: 'border-rose-500/20' },
    amber: { bg: 'bg-amber-500/10', text: 'text-amber-500', border: 'border-amber-500/20' },
    emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-500', border: 'border-emerald-500/20' },
  };

  const Icon = {
    shield: Shield,
    alert: AlertTriangle,
    activity: Activity,
    cpu: Cpu,
  }[icon];

  const theme = colorMap[color];

  return (
    <View className={`w-[48%] ${theme.bg} ${theme.border} border p-4 rounded-2xl mb-4 shadow-lg shadow-black/50`}>
      <View className="flex-row justify-between items-center mb-3">
        <Icon size={20} color={theme.text.includes('sky') ? '#38bdf8' : theme.text.includes('rose') ? '#f43f5e' : theme.text.includes('amber') ? '#f59e0b' : '#10b981'} />
        <Text className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${theme.bg} ${theme.text}`}>
          {trend}
        </Text>
      </View>
      <Text className="text-slate-400 text-xs font-medium">{label}</Text>
      <Text className="text-white text-xl font-bold mt-1">{value}</Text>
    </View>
  );
};

export default StatsCard;
