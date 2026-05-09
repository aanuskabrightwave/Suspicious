// ADMIN DASHBOARD - Antigravity
// TODO: Implement interactive zoom/pan for the SVG map

/**
 * apps/admin-dashboard/src/components/organisms/ThreatMap.tsx
 */
import React from 'react';
import { View, Dimensions } from 'react-native';
import Svg, { Path, Circle } from 'react-native-svg';

const ThreatMap = () => {
  const { width } = Dimensions.get('window');
  const mapWidth = width - 32;
  const mapHeight = 180;

  return (
    <View className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden mb-6 h-44 justify-center items-center">
      <Svg width={mapWidth} height={mapHeight} viewBox="0 0 400 200">
        <Path d="M20,100 L380,100 M20,60 L380,60 M20,140 L380,140" stroke="#1e293b" strokeWidth="1" />
        <Circle cx="80" cy="80" r="10" fill="#38bdf8" fillOpacity="0.2" />
        <Circle cx="80" cy="80" r="4" fill="#38bdf8" />
        
        <Circle cx="250" cy="120" r="25" fill="#f43f5e" fillOpacity="0.2" />
        <Circle cx="250" cy="120" r="6" fill="#f43f5e" />

        <Circle cx="320" cy="70" r="15" fill="#f59e0b" fillOpacity="0.2" />
        <Circle cx="320" cy="70" r="5" fill="#f59e0b" />
      </Svg>
    </View>
  );
};

export default ThreatMap;
