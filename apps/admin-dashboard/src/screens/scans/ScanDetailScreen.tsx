// ADMIN DASHBOARD - Antigravity
// TODO: Integrate Ayush's raw_ai_response JSON viewer

/**
 * apps/admin-dashboard/src/screens/scans/ScanDetailScreen.tsx
 */
import React from 'react';
import { ScrollView, View, Text } from 'react-native';
import RiskBadge from '../../components/atoms/RiskBadge';

const ScanDetailScreen = ({ route }: any) => {
  const { scan } = route.params;

  return (
    <ScrollView className="flex-1 bg-slate-950 p-6">
      <View className="bg-slate-900 p-6 rounded-2xl border border-slate-800 mb-6">
        <View className="flex-row justify-between items-start mb-6">
          <View className="flex-1 mr-4">
            <Text className="text-slate-500 text-xs font-bold uppercase mb-1">Target Resource</Text>
            <Text className="text-white text-lg font-bold" numberOfLines={2}>{scan.target}</Text>
          </View>
          <RiskBadge level={scan.riskLevel} />
        </View>

        <View className="h-2 bg-slate-800 rounded-full mb-6 overflow-hidden">
          <View 
            className="h-full bg-sky-500" 
            style={{ width: `${scan.riskScore}%`, backgroundColor: scan.riskScore > 70 ? '#f43f5e' : scan.riskScore > 40 ? '#f59e0b' : '#38bdf8' }} 
          />
        </View>

        <View className="flex-row justify-between">
          <View>
            <Text className="text-slate-500 text-[10px] font-bold uppercase">Confidence</Text>
            <Text className="text-white font-bold">{scan.confidence}%</Text>
          </View>
          <View>
            <Text className="text-slate-500 text-[10px] font-bold uppercase">Type</Text>
            <Text className="text-white font-bold">{scan.type}</Text>
          </View>
          <View>
            <Text className="text-slate-500 text-[10px] font-bold uppercase">Time</Text>
            <Text className="text-white font-bold">{new Date(scan.createdAt).toLocaleTimeString()}</Text>
          </View>
        </View>
      </View>

      <Text className="text-white text-lg font-bold mb-4">AI Analysis Report</Text>
      <View className="bg-slate-900 p-4 rounded-xl border border-slate-800 mb-6">
        <Text className="text-slate-300 leading-6">{scan.explanation || 'No detailed analysis provided by engine.'}</Text>
      </View>

      <Text className="text-white text-lg font-bold mb-4">Metadata Payload</Text>
      <View className="bg-slate-950 p-4 rounded-xl border border-slate-800">
        <Text className="text-emerald-500 font-mono text-xs">
          {JSON.stringify(scan.raw_ai_response || {}, null, 2)}
        </Text>
      </View>
    </ScrollView>
  );
};

export default ScanDetailScreen;
