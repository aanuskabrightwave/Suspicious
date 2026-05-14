export interface ScanUrlDto {
  url: string;
}

export interface ScanResult {
  url: string;
  riskScore: number;
  status: 'safe' | 'warning' | 'dangerous';
  threatType: string;
  reasons: string[];
}
