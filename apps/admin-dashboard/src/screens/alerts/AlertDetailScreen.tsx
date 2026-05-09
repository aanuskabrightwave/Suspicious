// ADMIN DASHBOARD - Antigravity
// TODO: Implement incident report PDF export

/**
 * apps/admin-dashboard/src/screens/alerts/AlertDetailScreen.tsx
 */
import React from 'react';
import { ScrollView, View, Text, TouchableOpacity } from 'react-native';
import { AlertTriangle, User, Globe, Clock, ShieldCheck } from 'lucide-react-native';
import RiskBadge from '../../components/atoms/RiskBadge';

const AlertDetailScreen = ({ route }: any) => {
  const { alert } = route.params;

  return (
    <ScrollView className="flex-1 bg-slate-950 p-6">
      <View className="items-center mb-8">
        <View className={`p-5 rounded-full mb-4 ${alert.riskLevel === 'critical' ? 'bg-rose-500/20' : 'bg-amber-500/20'}`}>
          <AlertTriangle color={alert.riskLevel === 'critical' ? '#f43f5e' : '#f59e0b'} size={40} />
        </View>
        <Text className="text-white text-2xl font-bold text-center">{alert.title}</Text>
        <View className="mt-2">
          <RiskBadge level={alert.riskLevel} />
        </View>
      </View>

      <View className="bg-slate-900 rounded-2xl border border-slate-800 p-5 mb-8">
        <Text className="text-slate-300 leading-6 text-base">{alert.message}</Text>
      </View>

      <View className="space-y-4">
        <View className="flex-row items-center bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <User color="#64748b" size={18} />
          <Text className="text-slate-400 ml-3 flex-1 text-sm">Affected User</Text>
          <Text className="text-white font-bold text-sm">{alert.affectedUser || 'System-wide'}</Text>
        </View>
        
        <View className="flex-row items-center bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <Globe color="#64748b" size={18} />
          <Text className="text-slate-400 ml-3 flex-1 text-sm">Originating Node</Text>
          <Text className="text-white font-bold text-sm">{alert.nodeId || 'AWS-US-EAST-1'}</Text>
        </View>

        <View className="flex-row items-center bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <Clock color="#64748b" size={18} />
          <Text className="text-slate-400 ml-3 flex-1 text-sm">Event Time</Text>
          <Text className="text-white font-bold text-sm">{new Date(alert.timestamp).toLocaleTimeString()}</Text>
        </View>
      </View>

      <TouchableOpacity className="mt-12 bg-sky-500 p-4 rounded-xl flex-row justify-center items-center">
        <ShieldCheck color="#fff" size={20} />
        <Text className="text-white font-bold ml-2">Archive Incident</Text>
      </TouchableOpacity>
    </ScrollView>
  );
};

export default AlertDetailScreen;
