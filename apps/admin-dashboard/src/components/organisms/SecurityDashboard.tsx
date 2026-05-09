// ADMIN DASHBOARD - Antigravity
// TODO: Add AI-generated security summary for the day

/**
 * apps/admin-dashboard/src/components/organisms/SecurityDashboard.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';
import ThreatTimeline from '../molecules/ThreatTimeline';
import DeviceStatusCard from '../molecules/DeviceStatusCard';

const SecurityDashboard = () => {
  return (
    <View className="mt-2 space-y-6">
      <View>
        <Text className="text-white text-lg font-bold mb-4 ml-1">Live Threat Feed</Text>
        <View className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl">
          <ThreatTimeline />
        </View>
      </View>

      <View>
        <Text className="text-white text-lg font-bold mb-4 ml-1">Network Integrity</Text>
        <DeviceStatusCard />
      </View>
    </View>
  );
};

export default SecurityDashboard;
