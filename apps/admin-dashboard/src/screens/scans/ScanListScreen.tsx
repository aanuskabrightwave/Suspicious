// ADMIN DASHBOARD - Antigravity
// TODO: Implement filter by scan type (URL, File, Image)

/**
 * apps/admin-dashboard/src/screens/scans/ScanListScreen.tsx
 */
import React, { useEffect, useState } from 'react';
import { FlatList, View, Text, TouchableOpacity } from 'react-native';
import { adminApi } from '../../services/api';
import ScanHistoryItem from '../../components/molecules/ScanHistoryItem';
import { Filter } from 'lucide-react-native';

const ScanListScreen = ({ navigation }: any) => {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await adminApi.getScans({ limit: 50, page: 1 });
        setScans(res.data.items);
      } catch (err) {
        console.error(err);
      }
    };
    fetchScans();
  }, []);

  return (
    <View className="flex-1 bg-slate-950">
      <View className="px-4 py-3 flex-row justify-between items-center border-b border-slate-900">
        <Text className="text-slate-400 text-xs font-bold uppercase tracking-widest">Total: {scans.length} Analysed</Text>
        <TouchableOpacity className="flex-row items-center bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
          <Filter color="#64748b" size={14} />
          <Text className="text-white ml-2 text-xs font-medium">Filter</Text>
        </TouchableOpacity>
      </View>
      <FlatList
        data={scans}
        renderItem={({ item }) => (
          <ScanHistoryItem 
            item={item} 
            onPress={() => navigation.navigate('ScanDetail', { scan: item })} 
          />
        )}
        keyExtractor={(item) => item.id}
        contentContainerStyle={{ padding: 16 }}
      />
    </View>
  );
};

export default ScanListScreen;
