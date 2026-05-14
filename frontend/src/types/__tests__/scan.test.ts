/**
 * Unit tests for TypeScript interfaces and type validation
 */

import {
  ScanResults,
  Vulnerability,
  DependencyVulnerability,
  SecretFinding,
  ScanStatus,
  ScanRequest,
  ScanResponse,
  ErrorResponse
} from '../scan';

describe('TypeScript Interface Tests', () => {
  describe('ScanResults', () => {
    it('should accept valid scan results', () => {
      const validScanResults: ScanResults = {
        scanId: 'test-123',
        repositoryUrl: 'https://github.com/user/repo',
        scanDate: '2023-12-01T10:00:00Z',
        summary: {
          critical: 2,
          high: 5,
          medium: 10,
          low: 3,
          total: 20
        },
        staticAnalysis: [],
        dependencies: [],
        secrets: [],
        scanDuration: 120.5,
        status: 'completed'
      };

      // Type checking - if this compiles, the interface is correct
      expect(validScanResults.scanId).toBe('test-123');
      expect(validScanResults.summary.total).toBe(20);
      expect(validScanResults.status).toBe('completed');
    });

    it('should handle all status types', () => {
      const statuses: ScanResults['status'][] = ['completed', 'failed', 'partial'];
      
      statuses.forEach(status => {
        const result: ScanResults = {
          scanId: 'test',
          repositoryUrl: 'https://github.com/user/repo',
          scanDate: '2023-12-01T10:00:00Z',
          summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
          staticAnalysis: [],
          dependencies: [],
          secrets: [],
          scanDuration: 0,
          status
        };
        
        expect(result.status).toBe(status);
      });
    });
  });

  describe('Vulnerability', () => {
    it('should accept valid vulnerability data', () => {
      const validVulnerability: Vulnerability = {
        tool: 'bandit',
        file: 'src/test.py',
        line: 42,
        severity: 'high',
        title: 'SQL Injection Vulnerability',
        description: 'Potential SQL injection found',
        recommendation: 'Use parameterized queries',
        cveId: 'CVE-2023-1234',
        confidence: 'high'
      };

      expect(validVulnerability.tool).toBe('bandit');
      expect(validVulnerability.line).toBe(42);
      expect(validVulnerability.severity).toBe('high');
    });

    it('should handle all tool types', () => {
      const tools: Vulnerability['tool'][] = ['bandit', 'trivy', 'detect-secrets'];
      
      tools.forEach(tool => {
        const vuln: Vulnerability = {
          tool,
          file: 'test.py',
          severity: 'medium',
          title: 'Test',
          description: 'Test description',
          recommendation: 'Fix it'
        };
        
        expect(vuln.tool).toBe(tool);
      });
    });

    it('should handle all severity levels', () => {
      const severities: Vulnerability['severity'][] = ['critical', 'high', 'medium', 'low'];
      
      severities.forEach(severity => {
        const vuln: Vulnerability = {
          tool: 'bandit',
          file: 'test.py',
          severity,
          title: 'Test',
          description: 'Test description',
          recommendation: 'Fix it'
        };
        
        expect(vuln.severity).toBe(severity);
      });
    });

    it('should handle optional fields', () => {
      const minimalVuln: Vulnerability = {
        tool: 'bandit',
        file: 'test.py',
        severity: 'medium',
        title: 'Test',
        description: 'Test description',
        recommendation: 'Fix it'
      };

      expect(minimalVuln.line).toBeUndefined();
      expect(minimalVuln.cveId).toBeUndefined();
      expect(minimalVuln.confidence).toBeUndefined();
    });
  });

  describe('DependencyVulnerability', () => {
    it('should extend Vulnerability with dependency-specific fields', () => {
      const depVuln: DependencyVulnerability = {
        tool: 'trivy',
        file: 'requirements.txt',
        severity: 'critical',
        title: 'Vulnerable Package',
        description: 'Package has known vulnerability',
        recommendation: 'Update to latest version',
        packageName: 'requests',
        installedVersion: '2.25.0',
        fixedVersion: '2.28.0',
        cveScore: 9.8
      };

      // Should have all Vulnerability fields
      expect(depVuln.tool).toBe('trivy');
      expect(depVuln.severity).toBe('critical');
      
      // Should have dependency-specific fields
      expect(depVuln.packageName).toBe('requests');
      expect(depVuln.installedVersion).toBe('2.25.0');
      expect(depVuln.fixedVersion).toBe('2.28.0');
      expect(depVuln.cveScore).toBe(9.8);
    });

    it('should handle optional dependency fields', () => {
      const minimalDepVuln: DependencyVulnerability = {
        tool: 'trivy',
        file: 'package.json',
        severity: 'high',
        title: 'Test',
        description: 'Test',
        recommendation: 'Test',
        packageName: 'lodash',
        installedVersion: '4.0.0'
      };

      expect(minimalDepVuln.fixedVersion).toBeUndefined();
      expect(minimalDepVuln.cveScore).toBeUndefined();
    });
  });

  describe('SecretFinding', () => {
    it('should extend Vulnerability with secret-specific fields', () => {
      const secretFinding: SecretFinding = {
        tool: 'detect-secrets',
        file: 'config.py',
        line: 15,
        severity: 'high',
        title: 'API Key Detected',
        description: 'Potential API key found in configuration',
        recommendation: 'Remove hardcoded secrets',
        secretType: 'api_key',
        entropy: 4.8,
        isVerified: true
      };

      // Should have all Vulnerability fields
      expect(secretFinding.tool).toBe('detect-secrets');
      expect(secretFinding.severity).toBe('high');
      
      // Should have secret-specific fields
      expect(secretFinding.secretType).toBe('api_key');
      expect(secretFinding.entropy).toBe(4.8);
      expect(secretFinding.isVerified).toBe(true);
    });

    it('should handle optional secret fields', () => {
      const minimalSecret: SecretFinding = {
        tool: 'detect-secrets',
        file: 'app.py',
        severity: 'medium',
        title: 'Test',
        description: 'Test',
        recommendation: 'Test',
        secretType: 'password'
      };

      expect(minimalSecret.entropy).toBeUndefined();
      expect(minimalSecret.isVerified).toBeUndefined();
    });
  });

  describe('ScanStatus', () => {
    it('should accept valid scan status', () => {
      const status: ScanStatus = {
        scanId: 'test-123',
        status: 'scanning',
        progress: 45,
        currentOperation: 'Running Bandit scan',
        estimatedTimeRemaining: 120
      };

      expect(status.scanId).toBe('test-123');
      expect(status.progress).toBe(45);
      expect(status.currentOperation).toBe('Running Bandit scan');
    });

    it('should handle all status types', () => {
      const statuses: ScanStatus['status'][] = ['initiated', 'cloning', 'scanning', 'completed', 'failed'];
      
      statuses.forEach(status => {
        const scanStatus: ScanStatus = {
          scanId: 'test',
          status,
          progress: 0
        };
        
        expect(scanStatus.status).toBe(status);
      });
    });

    it('should handle optional fields', () => {
      const minimalStatus: ScanStatus = {
        scanId: 'test-123',
        status: 'initiated',
        progress: 0
      };

      expect(minimalStatus.currentOperation).toBeUndefined();
      expect(minimalStatus.estimatedTimeRemaining).toBeUndefined();
    });
  });

  describe('ScanRequest', () => {
    it('should accept valid scan request', () => {
      const request: ScanRequest = {
        repositoryUrl: 'https://github.com/user/repo'
      };

      expect(request.repositoryUrl).toBe('https://github.com/user/repo');
    });
  });

  describe('ScanResponse', () => {
    it('should accept valid scan response', () => {
      const response: ScanResponse = {
        scanId: 'test-123',
        status: 'initiated'
      };

      expect(response.scanId).toBe('test-123');
      expect(response.status).toBe('initiated');
    });
  });

  describe('ErrorResponse', () => {
    it('should accept valid error response', () => {
      const errorResponse: ErrorResponse = {
        error: {
          code: 'REPO_TOO_LARGE',
          message: 'Repository size exceeds 200MB limit',
          details: {
            actualSize: '350MB',
            maxAllowed: '200MB'
          },
          suggestions: [
            'Try scanning a smaller repository',
            'Contact support for enterprise options'
          ]
        }
      };

      expect(errorResponse.error.code).toBe('REPO_TOO_LARGE');
      expect(errorResponse.error.suggestions).toHaveLength(2);
    });

    it('should handle minimal error response', () => {
      const minimalError: ErrorResponse = {
        error: {
          code: 'INVALID_URL',
          message: 'Invalid repository URL format'
        }
      };

      expect(minimalError.error.details).toBeUndefined();
      expect(minimalError.error.suggestions).toBeUndefined();
    });
  });

  describe('Type Safety', () => {
    it('should ensure scan results contain correct vulnerability types', () => {
      const scanResults: ScanResults = {
        scanId: 'test-123',
        repositoryUrl: 'https://github.com/user/repo',
        scanDate: '2023-12-01T10:00:00Z',
        summary: { critical: 1, high: 1, medium: 1, low: 0, total: 3 },
        staticAnalysis: [{
          tool: 'bandit',
          file: 'test.py',
          severity: 'high',
          title: 'Test',
          description: 'Test',
          recommendation: 'Test'
        }],
        dependencies: [{
          tool: 'trivy',
          file: 'requirements.txt',
          severity: 'critical',
          title: 'Test',
          description: 'Test',
          recommendation: 'Test',
          packageName: 'test-package',
          installedVersion: '1.0.0'
        }],
        secrets: [{
          tool: 'detect-secrets',
          file: 'config.py',
          severity: 'medium',
          title: 'Test',
          description: 'Test',
          recommendation: 'Test',
          secretType: 'api_key'
        }],
        scanDuration: 120,
        status: 'completed'
      };

      expect(scanResults.staticAnalysis).toHaveLength(1);
      expect(scanResults.dependencies).toHaveLength(1);
      expect(scanResults.secrets).toHaveLength(1);
      
      // Type checking - accessing specific fields should work
      expect(scanResults.dependencies[0].packageName).toBe('test-package');
      expect(scanResults.secrets[0].secretType).toBe('api_key');
    });
  });
});