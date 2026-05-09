// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/scanner/URLScannerScreen.tsx
 */
import React, { useState } from 'react';
import { View, TextInput, Alert } from 'react-native';
import { api } from '../../services/api';
import Button from '../../components/atoms/Button';
import LoadingIndicator from '../../components/atoms/LoadingIndicator';

export default function URLScannerScreen() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await api.scan(url);
      Alert.alert('Scan Result', res.data.explanation);
    } catch { Alert.alert('Error', 'Scan failed'); }
    setLoading(false);
  };

  return (
    <View className="flex-1 bg-slate-950 p-6">
      <TextInput className="bg-slate-900 text-white p-4 rounded-xl mb-4" placeholder="Enter URL" value={url} onChangeText={setUrl} />
      <Button title="Scan with AI" onPress={handleScan} loading={loading} />
      {loading && <LoadingIndicator label="AI is thinking..." />}
    </View>
  );
}
