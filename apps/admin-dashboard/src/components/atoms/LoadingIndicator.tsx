// ADMIN DASHBOARD - Antigravity
// TODO: Use Lottie for more complex AI "thinking" animations

/*
 * apps/admin-dashboard/src/components/atoms/LoadingIndicator.tsx
 */
import React, { useEffect } from 'react';
import { View, Text, Animated, Easing } from 'react-native';
import { ShieldAlert } from 'lucide-react-native';

const LoadingIndicator = () => {
  const spinValue = new Animated.Value(0);

  useEffect(() => {
    Animated.loop(
      Animated.timing(spinValue, {
        toValue: 1,
        duration: 2000,
        easing: Easing.linear,
        useNativeDriver: true,
      })
    ).start();
  }, []);

  const spin = spinValue.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <View className="items-center justify-center p-8">
      <Animated.View style={{ transform: [{ rotate: spin }] }}>
        <ShieldAlert color="#38bdf8" size={48} />
      </Animated.View>
      <Text className="text-slate-400 mt-4 font-mono text-xs uppercase tracking-widest">AI Engine Processing...</Text>
    </View>
  );
};

export default LoadingIndicator;
