// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/screens/scanner/ScanResultModal.tsx
 */
import React from 'react';
import { View, Text, Modal } from 'react-native';
import RiskBadge from '../../components/atoms/RiskBadge';
import Button from '../../components/atoms/Button';

export default function ScanResultModal({ visible, scan, onClose }: any) {
  if (!scan) return null;
  return (
    <Modal visible={visible} transparent animationType="slide">
      <View className="flex-1 justify-end bg-black/50">
        <View className="bg-slate-900 p-6 rounded-t-3xl">
          <RiskBadge level={scan.riskLevel} />
          <Text className="text-white text-lg mt-4">{scan.explanation}</Text>
          <Button title="Close" onPress={onClose} className="mt-6" />
        </View>
      </View>
    </Modal>
  );
}
