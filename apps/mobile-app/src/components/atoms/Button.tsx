// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/components/atoms/Button.tsx
 */
import React from 'react';
import { TouchableOpacity, Text, ActivityIndicator } from 'react-native';

export default function Button({ title, onPress, loading, className }: any) {
  return (
    <TouchableOpacity className={`bg-sky-500 p-4 rounded-xl items-center ${className}`} onPress={onPress} disabled={loading}>
      {loading ? <ActivityIndicator color="#fff" /> : <Text className="text-white font-bold">{title}</Text>}
    </TouchableOpacity>
  );
}
