// ADMIN DASHBOARD - Antigravity
/**
 * apps/admin-dashboard/src/types/index.ts
 */
export type Role = 'superadmin' | 'analyst' | 'support' | 'user';
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  riskLevel?: RiskLevel;
  createdAt: string;
  lastLogin?: string;
}

export interface Scan {
  id: string;
  userId: string;
  target: string;
  type: 'URL' | 'File' | 'Image';
  riskScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  explanation: string;
  raw_ai_response: any;
  createdAt: string;
}

export interface Alert {
  id: string;
  title: string;
  message: string;
  riskLevel: RiskLevel;
  affectedUser?: string;
  nodeId?: string;
  timestamp: string;
  isRead: boolean;
}

export interface ThreatLog {
  id: string;
  event: string;
  severity: RiskLevel;
  timestamp: string;
}
