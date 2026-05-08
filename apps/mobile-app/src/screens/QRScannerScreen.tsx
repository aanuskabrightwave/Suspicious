import React, { useState } from 'react';
import { View, Text, StyleSheet, Button, Alert } from 'react-native';
import api from '../api/axiosConfig';

// ======================================
// ANUSKA WORK AREA
// Integrate react-native-camera or vision-camera
// Handle QR scan logic and UI
// Connect with backend scan API
// ======================================

export default function QRScannerScreen({ navigation }: any) {
  const [scanning, setScanning] = useState(false);

  const handleMockScan = async () => {
    setScanning(true);
    try {
      // Mock API call to Backend (which routes to AI Engine)
      const mockQrData = 'http://suspicious-bank-login.com';
      const response = await api.post('/scan/qr', { data: mockQrData });
      
      if (response.data.riskLevel === 'HIGH') {
        Alert.alert('⚠️ Warning', 'Malicious QR Code Detected!');
      } else {
        Alert.alert('✅ Safe', 'QR Code is safe to open.');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Failed to scan QR code.');
    } finally {
      setScanning(false);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>QR Code Scanner</Text>
      <View style={styles.cameraBox}>
        <Text style={styles.cameraText}>Camera View Placeholder</Text>
        {/* TODO: Add Camera Component here */}
      </View>
      <Button 
        title={scanning ? "Scanning..." : "Simulate QR Scan"} 
        onPress={handleMockScan} 
        disabled={scanning}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, alignItems: 'center', padding: 20 },
  title: { fontSize: 24, fontWeight: 'bold', marginBottom: 20 },
  cameraBox: { width: 300, height: 300, backgroundColor: '#ccc', justifyContent: 'center', alignItems: 'center', marginBottom: 20 },
  cameraText: { color: '#666' }
});
