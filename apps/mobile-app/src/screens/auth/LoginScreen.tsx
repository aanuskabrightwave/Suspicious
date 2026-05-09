// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/auth/LoginScreen.tsx
 */
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity } from 'react-native';
import { useDispatch } from 'react-redux';
import { setCredentials } from '../../redux/slices/authSlice';
import { api } from '../../services/api';
import Button from '../../components/atoms/Button';

export default function LoginScreen() {
  const [email, setEmail] = useState('');
  const [pass, setPass] = useState('');
  const dispatch = useDispatch();

  const handleLogin = async () => {
    try {
      const res = await api.login({ email, password: pass });
      dispatch(setCredentials(res.data));
    } catch (e) { console.error(e); }
  };

  return (
    <View className="flex-1 bg-slate-950 p-6 justify-center">
      <Text className="text-white text-3xl font-bold mb-8">Cyber Shield</Text>
      <TextInput className="bg-slate-900 text-white p-4 rounded-xl mb-4" placeholder="Email" value={email} onChangeText={setEmail} />
      <TextInput className="bg-slate-900 text-white p-4 rounded-xl mb-6" placeholder="Password" secureTextEntry value={pass} onChangeText={setPass} />
      <Button title="Login" onPress={handleLogin} />
    </View>
  );
}