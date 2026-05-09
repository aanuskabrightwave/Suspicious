// ADMIN DASHBOARD - Antigravity
// TODO: Integrate with real-time device health metrics

/**
 * apps/admin-dashboard/src/components/molecules/DeviceStatusCard.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';
import { Smartphone, Server } from 'lucide-react-native';

const DeviceStatusCard = () => {
  const devices = [
    { name: 'US-EDGE-NODE-1', status: 'Online', type: 'Server' },
    { name: 'SEC-ADMIN-MOBILE', status: 'Warning', type: 'Mobile' },
  ];

  return (
    <View className="flex-row space-x-4">
      {devices.map((d, i) => (
        <View key={i} className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex-1">
          <View className="flex-row justify-between items-center mb-2">
            {d.type === 'Server' ? <Server color="#64748b" size={16} /> : <Smartphone color="#64748b" size={16} />}
            <View className={`h-2 w-2 rounded-full ${d.status === 'Online' ? 'bg-emerald-500' : 'bg-amber-500'}`} />
          </View>
          <Text className="text-white font-bold text-xs" numberOfLines={1}>{d.name}</Text>
          <Text className="text-slate-500 text-[10px] mt-1">{d.status}</Text>
        </View>
      ))}
    </View>
  );
};

export default DeviceStatusCard;
