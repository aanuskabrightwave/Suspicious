// ADMIN DASHBOARD - Antigravity
// TODO: Implement AI-driven password strength analyzer

/**
 * apps/admin-dashboard/src/screens/auth/LoginScreen.tsx
 */
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, KeyboardAvoidingView, Platform } from 'react-native';
import { useDispatch } from 'react-redux';
import { setCredentials } from '../../redux/slices/authSlice';
import { ShieldCheck, Eye, EyeOff } from 'lucide-react-native';
import Button from '../../components/atoms/Button';
import { adminApi } from '../../services/api';

const LoginScreen = ({ navigation }: any) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const dispatch = useDispatch();

  const handleLogin = async () => {
    if (!email || !password) return setError('Credentials required');
    setLoading(true);
    setError('');
    try {
      const res = await adminApi.login({ email, password });
      dispatch(setCredentials(res.data));
    } catch (err: any) {
      setError(err.response?.data?.message || 'Security validation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView 
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      className="flex-1 bg-slate-950 px-6 justify-center"
    >
      <View className="items-center mb-12">
        <View className="bg-sky-500/10 p-4 rounded-2xl mb-4">
          <ShieldCheck color="#38bdf8" size={48} />
        </View>
        <Text className="text-white text-3xl font-bold tracking-tight">Cyber Shield</Text>
        <Text className="text-slate-400 text-sm mt-2">Enterprise Admin Terminal</Text>
      </View>

      <View className="space-y-4">
        <View>
          <Text className="text-slate-300 mb-2 ml-1 text-xs uppercase font-semibold">Security ID</Text>
          <TextInput
            placeholder="admin@cybershield.ai"
            placeholderTextColor="#475569"
            className="bg-slate-900 text-white p-4 rounded-xl border border-slate-800 focus:border-sky-500"
            value={email}
            onChangeText={setEmail}
            autoCapitalize="none"
          />
        </View>

        <View>
          <Text className="text-slate-300 mb-2 ml-1 text-xs uppercase font-semibold">Access Key</Text>
          <View className="relative">
            <TextInput
              placeholder="••••••••"
              placeholderTextColor="#475569"
              className="bg-slate-900 text-white p-4 rounded-xl border border-slate-800 focus:border-sky-500"
              value={password}
              onChangeText={setPassword}
              secureTextEntry={!showPassword}
            />
            <TouchableOpacity 
              className="absolute right-4 top-4"
              onPress={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff color="#64748b" size={20} /> : <Eye color="#64748b" size={20} />}
            </TouchableOpacity>
          </View>
        </View>

        {error ? <Text className="text-rose-500 text-center text-sm font-medium">{error}</Text> : null}

        <Button 
          title="Authenticate" 
          onPress={handleLogin} 
          loading={loading}
          variant="primary"
          className="mt-4"
        />

        <TouchableOpacity onPress={() => navigation.navigate('ResetPassword')}>
          <Text className="text-sky-500 text-center mt-4 text-sm font-medium">Request Key Reset</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

export default LoginScreen;
