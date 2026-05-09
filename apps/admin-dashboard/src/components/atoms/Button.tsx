// ADMIN DASHBOARD - Antigravity
// TODO: Implement haptic feedback on button press

/**
 * apps/admin-dashboard/src/components/atoms/Button.tsx
 */
import React from 'react';
import { TouchableOpacity, Text, ActivityIndicator } from 'react-native';

interface Props {
  title: string;
  onPress: () => void;
  loading?: boolean;
  variant?: 'primary' | 'outline' | 'ghost' | 'danger';
  className?: string;
  disabled?: boolean;
}

const Button = ({ title, onPress, loading, variant = 'primary', className = '', disabled }: Props) => {
  const baseStyle = "p-4 rounded-xl items-center justify-center flex-row";
  const variantStyles = {
    primary: "bg-sky-500 shadow-lg shadow-sky-500/20",
    outline: "bg-transparent border border-slate-800",
    ghost: "bg-transparent",
    danger: "bg-rose-500",
  };
  const textStyles = {
    primary: "text-white font-bold",
    outline: "text-white font-bold",
    ghost: "text-slate-400 font-bold",
    danger: "text-white font-bold",
  };

  return (
    <TouchableOpacity 
      onPress={onPress} 
      disabled={loading || disabled}
      className={`${baseStyle} ${variantStyles[variant]} ${disabled || loading ? 'opacity-50' : ''} ${className}`}
    >
      {loading ? (
        <ActivityIndicator color={variant === 'outline' ? '#38bdf8' : '#fff'} className="mr-2" />
      ) : null}
      <Text className={textStyles[variant]}>{title}</Text>
    </TouchableOpacity>
  );
};

export default Button;
