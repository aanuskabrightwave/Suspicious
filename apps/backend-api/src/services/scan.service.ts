import { ScanUrlDto, ScanResult } from '../types/scan.types';
import { ScanRepository } from '../repositories/scan.repository';
import { Scan } from '@prisma/client';

export class ScanService {
  private scanRepository: ScanRepository;

  constructor() {
    this.scanRepository = new ScanRepository();
  }

  /**
   * Performs a heuristic analysis on a URL and PERSISTS the result to the database.
   */
  public async analyzeUrl(data: ScanUrlDto, userId: string): Promise<Scan> {
    const { url } = data;
    const reasons: string[] = [];
    let riskScore = 0;

    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // 1. Suspicious Keyword Detection
    const suspiciousKeywords = ['login', 'verify', 'banking', 'reward', 'free', 'update', 'secure', 'account', 'signin'];
    const foundKeywords = suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw));
    if (foundKeywords.length > 0) {
      riskScore += foundKeywords.length * 15;
      reasons.push(`Suspicious keywords detected: ${foundKeywords.join(', ')}`);
    }

    // 2. IP-Based URL Detection
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipRegex.test(domain)) {
      riskScore += 40;
      reasons.push('URL uses an IP address instead of a domain name');
    }

    // 3. Excessively Long URL Detection
    if (url.length > 100) {
      riskScore += 20;
      reasons.push('Excessively long URL often used for obfuscation');
    }

    // 4. Suspicious TLD Detection
    const suspiciousTlds = ['.xyz', '.top', '.tk', '.pw', '.ga', '.ml', '.cf', '.gq'];
    const hasSuspiciousTld = suspiciousTlds.some(tld => domain.endsWith(tld));
    if (hasSuspiciousTld) {
      riskScore += 25;
      reasons.push('High-risk TLD associated with spam/malware');
    }

    // 5. Punycode Detection
    if (domain.includes('xn--')) {
      riskScore += 50;
      reasons.push('Punycode detected; potential homograph attack');
    }

    riskScore = Math.min(riskScore, 100);

    let status = 'safe';
    let threatType = 'none';

    if (riskScore > 70) {
      status = 'dangerous';
      threatType = 'phishing';
    } else if (riskScore > 30) {
      status = 'warning';
      threatType = 'suspicious';
    }

    // 6. PERSISTENCE: Save the result to PostgreSQL
    return this.scanRepository.createScan({
      userId,
      url,
      riskScore,
      status,
      threatType,
      reasons,
    });
  }

  /**
   * Retrieves the full scan history for an authenticated user.
   */
  public async getHistory(userId: string): Promise<Scan[]> {
    return this.scanRepository.findHistoryByUserId(userId);
  }
}
