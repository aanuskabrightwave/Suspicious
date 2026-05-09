// ADMIN DASHBOARD - Antigravity
// TODO: Implement schema-based validation using Zod

/**
 * apps/admin-dashboard/src/utils/validators.ts
 */
export const validateEmail = (email: string): boolean => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

export const validatePassword = (password: string): boolean => {
  return password.length >= 8;
};

export const getRiskColor = (level: string) => {
  switch (level) {
    case 'critical': return '#f43f5e';
    case 'high': return '#fb7185';
    case 'medium': return '#fbbf24';
    case 'low': return '#38bdf8';
    default: return '#10b981';
  }
};
