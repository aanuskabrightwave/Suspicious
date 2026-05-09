/**
 * apps/admin-dashboard/src/components/molecules/ThreatTimeline.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';

const ThreatTimeline = () => {
  const events = [
    { time: '10:45', msg: 'Multiple failed logins detected from 192.168.1.1', level: 'high' },
    { time: '10:30', msg: 'AI Engine scan completed: benign', level: 'safe' },
    { time: '10:15', msg: 'New administrative operative registered', level: 'low' },
  ];

  return (
    <View className="mt-4">
      {events.map((e, i) => (
        <View key={i} className="flex-row mb-4">
          <View className="items-center mr-4">
            <View className={`h-3 w-3 rounded-full ${e.level === 'high' ? 'bg-rose-500' : 'bg-slate-700'}`} />
            {i !== events.length - 1 && <View className="w-0.5 flex-1 bg-slate-800 mt-1" />}
          </View>
          <View className="flex-1 pb-4">
            <Text className="text-slate-500 text-[10px] font-bold">{e.time}</Text>
            <Text className="text-slate-300 text-xs mt-1">{e.msg}</Text>
          </View>
        </View>
      ))}
    </View>
  );
};

export default ThreatTimeline;
