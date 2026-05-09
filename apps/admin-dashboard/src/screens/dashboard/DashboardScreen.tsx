// ADMIN DASHBOARD - Antigravity
// TODO: Implement custom interval selector for stats refreshing

/**
 * apps/admin-dashboard/src/screens/dashboard/DashboardScreen.tsx
 */
import React, { useEffect, useState } from 'react';
import { ScrollView, View, Text, RefreshControl } from 'react-native';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../redux/store';
import { setDashboardStats } from '../../redux/slices/dashboardSlice';
import StatsCard from './StatsCard';
import SecurityDashboard from '../../components/organisms/SecurityDashboard';
import ThreatMap from '../../components/organisms/ThreatMap';
import { adminApi } from '../../services/api';
import { socketService } from '../../services/socket';

const DashboardScreen = () => {
  const [refreshing, setRefreshing] = useState(false);
  const stats = useSelector((state: RootState) => state.dashboard.stats);
  const dispatch = useDispatch();

  const loadData = async () => {
    try {
      const res = await adminApi.getStats();
      dispatch(setDashboardStats(res.data));
    } catch (err) {
      console.error('Failed to load dashboard stats', err);
    }
  };

  useEffect(() => {
    loadData();
    socketService.connect();
    return () => socketService.disconnect();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  return (
    <ScrollView 
      className="flex-1 bg-slate-950"
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#38bdf8" />}
    >
      <View className="p-4">
        <View className="flex-row flex-wrap justify-between mb-4">
          <StatsCard 
            label="Total Scans" 
            value={stats.totalScans.toLocaleString()} 
            trend="+12%" 
            icon="shield" 
            color="sky"
          />
          <StatsCard 
            label="Active Threats" 
            value={stats.activeThreats.toString()} 
            trend="-5%" 
            icon="alert" 
            color="rose"
          />
          <StatsCard 
            label="Risk Level" 
            value={`${stats.highRiskPercentage}%`} 
            trend="Stable" 
            icon="activity" 
            color="amber"
          />
          <StatsCard 
            label="Sys Health" 
            value={`${stats.systemHealth}%`} 
            trend="Optimal" 
            icon="cpu" 
            color="emerald"
          />
        </View>

        <Text className="text-white text-lg font-bold mb-4 ml-1">Global Threat Distribution</Text>
        <ThreatMap />

        <SecurityDashboard />
      </View>
    </ScrollView>
  );
};

export default DashboardScreen;
