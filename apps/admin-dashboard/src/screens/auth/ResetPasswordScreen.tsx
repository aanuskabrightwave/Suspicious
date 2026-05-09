// ADMIN DASHBOARD - Antigravity
// TODO: Integrate with SMTP for 2FA reset links

/**
 * apps/admin-dashboard/src/screens/auth/ResetPasswordScreen.tsx
 */
import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity } from 'react-native';
import { ArrowLeft } from 'lucide-react-native';
import Button from '../../components/atoms/Button';

const ResetPasswordScreen = ({ navigation }: any) => {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  return (
    <View className="flex-1 bg-slate-950 p-6 pt-16">
      <TouchableOpacity onPress={() => navigation.goBack()} className="mb-8">
        <ArrowLeft color="#fff" size={24} />
      </TouchableOpacity>

      <Text className="text-white text-2xl font-bold mb-2">Reset Access Key</Text>
      <Text className="text-slate-400 mb-8">Enter your security ID to receive a verification link.</Text>

      {!sent ? (
        <View className="space-y-4">
          <TextInput
            placeholder="admin@cybershield.ai"
            placeholderTextColor="#475569"
            className="bg-slate-900 text-white p-4 rounded-xl border border-slate-800"
            value={email}
            onChangeText={setEmail}
          />
          <Button 
            title="Send Verification Link" 
            onPress={() => setSent(true)} 
            variant="primary"
          />
        </View>
      ) : (
        <View className="items-center mt-10">
          <View className="bg-emerald-500/20 p-4 rounded-full mb-4">
            <Text className="text-emerald-500 font-bold">✓</Text>
          </View>
          <Text className="text-white text-lg font-semibold">Verification Sent</Text>
          <Text className="text-slate-400 text-center mt-2">Check your encrypted inbox for the reset link.</Text>
          <Button 
            title="Back to Login" 
            onPress={() => navigation.navigate('Login')} 
            variant="outline"
            className="mt-8 w-full"
          />
        </View>
      )}
    </View>
  );
};

export default ResetPasswordScreen;
