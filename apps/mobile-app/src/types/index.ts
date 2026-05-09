// ANUSKA WORK AREA
/**
 * apps/mobile-app/src/types/index.ts
 */
export interface User { id: string; email: string; name: string; }
export interface Scan { id: string; target: string; riskLevel: string; explanation: string; }
export interface Alert { id: string; title: string; riskLevel: string; timestamp: string; }
