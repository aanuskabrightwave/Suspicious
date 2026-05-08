import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useSelector } from 'react-redux';
import { RootState } from '../store';

// ======================================
// ANUSKA WORK AREA
// Build main dashboard UI logic here
// Display recent threats from Redux store
// Add navigation to Scanner, History, Settings
// ======================================

export default function DashboardScreen({ navigation }: any) {
  const threats = useSelector((state: RootState) => state.threats.threats);

  return (
    <View style={styles.container}>
      <Text style={styles.header}>Shield Status</Text>
      <View style={styles.statusCard}>
        <Text style={styles.statusText}>✅ Device Protected</Text>
      </View>

      <Text style={styles.sectionTitle}>Quick Actions</Text>
      <View style={styles.actionsGrid}>
        <TouchableOpacity style={styles.actionBtn} onPress={() => navigation.navigate('QRScanner')}>
          <Text style={styles.actionText}>Scan QR</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn}>
          <Text style={styles.actionText}>Check Link</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.sectionTitle}>Recent Alerts ({threats.length})</Text>
      {/* TODO: Map over threats and render ThreatCard components */}
      {threats.length === 0 && <Text style={styles.noThreats}>No recent threats detected.</Text>}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, backgroundColor: '#f5f5f5' },
  header: { fontSize: 28, fontWeight: 'bold', marginBottom: 20 },
  statusCard: { backgroundColor: '#4CAF50', padding: 20, borderRadius: 10, alignItems: 'center', marginBottom: 30 },
  statusText: { color: 'white', fontSize: 18, fontWeight: 'bold' },
  sectionTitle: { fontSize: 20, fontWeight: 'bold', marginBottom: 15 },
  actionsGrid: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 30 },
  actionBtn: { backgroundColor: '#2196F3', padding: 15, borderRadius: 8, width: '48%', alignItems: 'center' },
  actionText: { color: 'white', fontWeight: 'bold' },
  noThreats: { color: '#888', fontStyle: 'italic' }
});
