// ADMIN DASHBOARD - Antigravity
// TODO: Implement fuzzy search for user filtering

/**
 * apps/admin-dashboard/src/screens/users/UserListScreen.tsx
 */
import React, { useEffect } from 'react';
import { FlatList, View, Text, TouchableOpacity } from 'react-native';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../redux/store';
import { setUsers } from '../../redux/slices/userSlice';
import { adminApi } from '../../services/api';
import { Search, ChevronRight } from 'lucide-react-native';

const UserListScreen = ({ navigation }: any) => {
  const { users } = useSelector((state: RootState) => state.users);
  const dispatch = useDispatch();

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const res = await adminApi.getUsers();
        dispatch(setUsers(res.data));
      } catch (err) {
        console.error(err);
      }
    };
    fetchUsers();
  }, []);

  const renderUser = ({ item }: any) => (
    <TouchableOpacity 
      onPress={() => navigation.navigate('UserDetail', { user: item })}
      className="flex-row items-center bg-slate-900/50 p-4 rounded-xl mb-3 border border-slate-800"
    >
      <View className="h-12 w-12 rounded-full bg-slate-800 items-center justify-center border border-slate-700">
        <Text className="text-white font-bold">{item.name.charAt(0)}</Text>
      </View>
      <View className="flex-1 ml-4">
        <Text className="text-white font-semibold text-base">{item.name}</Text>
        <Text className="text-slate-400 text-xs">{item.email}</Text>
      </View>
      <View className="items-end">
        <View className={`px-2 py-1 rounded-full ${item.role === 'superadmin' ? 'bg-purple-500/20' : 'bg-slate-800'}`}>
          <Text className={`text-[10px] font-bold ${item.role === 'superadmin' ? 'text-purple-400' : 'text-slate-400'}`}>
            {item.role.toUpperCase()}
          </Text>
        </View>
        <ChevronRight color="#475569" size={16} className="mt-1" />
      </View>
    </TouchableOpacity>
  );

  return (
    <View className="flex-1 bg-slate-950 p-4">
      <View className="flex-row items-center bg-slate-900 border border-slate-800 p-3 rounded-xl mb-6">
        <Search color="#64748b" size={18} />
        <Text className="text-slate-500 ml-2 text-sm">Search 1,240 operatives...</Text>
      </View>
      <FlatList
        data={users}
        renderItem={renderUser}
        keyExtractor={(item) => item.id}
        showsVerticalScrollIndicator={false}
      />
    </View>
  );
};

export default UserListScreen;
