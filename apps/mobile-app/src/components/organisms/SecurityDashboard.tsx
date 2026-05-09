// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/components/organisms/SecurityDashboard.tsx
 */
import React from 'react';
import { View, Text } from 'react-native';
import StatsCard from '../../screens/dashboard/StatsCard';

export default function SecurityDashboard() {
  return (
    <View>
      <StatsCard label="Scans Today" value="12" />
      <StatsCard label="Threats Neutralized" value="2" />
    </View>
  );
}
