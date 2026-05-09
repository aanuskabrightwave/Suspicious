// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/components/atoms/LoadingIndicator.tsx
 */
import React from 'react';
import { View, Text, ActivityIndicator } from 'react-native';

export default function LoadingIndicator({ label }: any) {
  return (
    <View className="items-center p-4">
      <ActivityIndicator size="large" color="#0ea5e9" />
      <Text className="text-slate-400 mt-2">{label}</Text>
    </View>
  );
}
