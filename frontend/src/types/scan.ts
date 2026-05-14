/**
 * Core data models for CodeShield security scanning
 */

export interface ScanResults {
  scanId: string;
  repositoryUrl: string;
  scanDate: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  staticAnalysis: Vulnerability[];
  dependencies: DependencyVulnerability[];
  secrets: SecretFinding[];
  scanDuration: number;
  status: 'completed' | 'failed' | 'partial';
}

export interface Vulnerability {
  tool: 'bandit' | 'trivy' | 'detect-secrets';
  file: string;
  line?: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  recommendation: string;
  cveId?: string;
  confidence?: 'high' | 'medium' | 'low';
}

export interface DependencyVulnerability extends Vulnerability {
  packageName: string;
  installedVersion: string;
  fixedVersion?: string;
  cveScore?: number;
}

export interface SecretFinding extends Vulnerability {
  secretType: string;
  entropy?: number;
  isVerified?: boolean;
}

export interface ScanStatus {
  scanId: string;
  status: 'initiated' | 'cloning' | 'scanning' | 'completed' | 'failed';
  progress: number;
  currentOperation?: string;
  estimatedTimeRemaining?: number;
}

export interface ScanRequest {
  repositoryUrl: string;
}

export interface ScanResponse {
  scanId: string;
  status: string;
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
    suggestions?: string[];
  };
}