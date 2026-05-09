// ADMIN DASHBOARD - Antigravity
// TODO: Implement alert escalation to PagerDuty/Slack

/**
 * apps/admin-dashboard/src/screens/alerts/AlertListScreen.tsx
 */
import React from 'react';
import { FlatList, View, Text, TouchableOpacity } from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '../../redux/store';
import { markAlertAsRead } from '../../redux/slices/alertSlice';
import { Bell } from 'lucide-react-native';
import RiskBadge from '../../components/atoms/RiskBadge';

const AlertListScreen = ({ navigation }: any) => {
  const { alerts } = useSelector((state: RootState) => state.alerts);
  const dispatch = useDispatch();

  const renderAlert = ({ item }: any) => (
    <TouchableOpacity 
      onPress={() => {
        dispatch(markAlertAsRead(item.id));
        navigation.navigate('AlertDetail', { alert: item });
      }}
      className={`p-4 mb-3 rounded-xl border ${item.isRead ? 'bg-slate-900/40 border-slate-800/50' : 'bg-slate-900 border-slate-800 shadow-md shadow-black'}`}
    >
      <View className="flex-row justify-between mb-2">
        <View className="flex-row items-center">
          <View className={`w-2 h-2 rounded-full mr-2 ${item.isRead ? 'bg-transparent' : 'bg-sky-500'}`} />
          <Text className={`font-bold ${item.isRead ? 'text-slate-400' : 'text-white'}`}>{item.title}</Text>
        </View>
        <RiskBadge level={item.riskLevel} />
      </View>
      <Text className="text-slate-400 text-sm mb-3" numberOfLines={2}>{item.message}</Text>
      <Text className="text-slate-500 text-[10px] font-medium">{new Date(item.timestamp).toLocaleString()}</Text>
    </TouchableOpacity>
  );

  return (
    <View className="flex-1 bg-slate-950 p-4">
      {alerts.length === 0 ? (
        <View className="flex-1 items-center justify-center opacity-30">
          <Bell color="#64748b" size={64} />
          <Text className="text-slate-400 mt-4 font-semibold">No pending threats detected</Text>
        </View>
      ) : (
        <FlatList
          data={alerts}
          renderItem={renderAlert}
          keyExtractor={(item) => item.id}
        />
      )}
    </View>
  );
};

export default AlertListScreen;
