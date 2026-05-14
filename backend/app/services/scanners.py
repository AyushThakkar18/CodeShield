"""
Security scanner services for CodeShield
"""

import asyncio
import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

from ..models.scan import Vulnerability, DependencyVulnerability, SecretFinding
from ..models.config import BanditConfig, TrivyConfig, SecretScannerConfig


class BaseScannerService(ABC):
    """Base class for all security scanners"""
    
    def __init__(self, config: Any):
        self.config = config
    
    @abstractmethod
    async def scan(self, repo_path: str) -> List[Any]:
        """Perform security scan on the repository"""
        pass
    
    @abstractmethod
    def parse_results(self, raw_results: str) -> List[Any]:
        """Parse raw scanner output into standardized format"""
        pass


class BanditScanner(BaseScannerService):
    """Bandit static analysis scanner for Python code vulnerabilities"""
    
    def __init__(self, config: BanditConfig):
        super().__init__(config)
    
    async def scan(self, repo_path: str) -> List[Vulnerability]:
        """Run Bandit scan on the repository"""
        try:
            # Build Bandit command using Python module
            cmd = [
                "python", "-m", "bandit",
                "-r",  # Recursive
                "-f", self.config.format,  # JSON format
                "-ll",  # Low confidence and severity
            ]
            
            # Add exclusions
            if self.config.exclude_dirs:
                exclude_paths = ",".join(self.config.exclude_dirs)
                cmd.extend(["--exclude", exclude_paths])
            
            # Add the repository path
            cmd.append(repo_path)
            
            # Run Bandit
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path
            )
            
            stdout, stderr = await process.communicate()
            
            # Bandit returns non-zero exit code when vulnerabilities are found
            # This is expected behavior, so we don't treat it as an error
            if process.returncode not in [0, 1]:
                raise RuntimeError(f"Bandit scan failed: {stderr.decode()}")
            
            raw_results = stdout.decode()
            return self.parse_results(raw_results)
            
        except Exception as e:
            raise RuntimeError(f"Bandit scan error: {str(e)}")
    
    def parse_results(self, raw_results: str) -> List[Vulnerability]:
        """Parse Bandit JSON output into Vulnerability objects"""
        try:
            if not raw_results.strip():
                return []
            
            data = json.loads(raw_results)
            vulnerabilities = []
            
            # Parse Bandit results
            results = data.get("results", [])
            
            for result in results:
                # Map Bandit severity to our standard levels
                severity_map = {
                    "LOW": "low",
                    "MEDIUM": "medium", 
                    "HIGH": "high"
                }
                
                # Map Bandit confidence to our standard levels
                confidence_map = {
                    "LOW": "low",
                    "MEDIUM": "medium",
                    "HIGH": "high"
                }
                
                vulnerability = Vulnerability(
                    tool="bandit",
                    file=result.get("filename", "unknown"),
                    line=result.get("line_number"),
                    severity=severity_map.get(result.get("issue_severity", "LOW"), "low"),
                    title=result.get("test_name", "Unknown vulnerability"),
                    description=result.get("issue_text", "No description available"),
                    recommendation=self._get_recommendation(result.get("test_id", "")),
                    confidence=confidence_map.get(result.get("issue_confidence", "LOW"), "low")
                )
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Bandit results: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing Bandit results: {str(e)}")
    
    def _get_recommendation(self, test_id: str) -> str:
        """Get fix recommendation based on Bandit test ID"""
        recommendations = {
            "B101": "Remove or replace assert statements in production code",
            "B102": "Use subprocess with shell=False or validate input thoroughly",
            "B103": "Set file permissions explicitly using os.chmod()",
            "B104": "Bind to specific interfaces instead of 0.0.0.0",
            "B105": "Use secrets module or environment variables for passwords",
            "B106": "Use secrets module or environment variables for passwords",
            "B107": "Use secrets module or environment variables for passwords",
            "B108": "Use mkstemp() or NamedTemporaryFile() instead",
            "B110": "Use try/except blocks instead of bare except",
            "B112": "Use try/except blocks instead of bare except",
            "B201": "Use subprocess with shell=False",
            "B301": "Use pickle.loads() with caution or consider alternatives",
            "B302": "Use marshal.loads() with caution or consider alternatives",
            "B303": "Use hashlib with secure algorithms (SHA-256, SHA-3)",
            "B304": "Use cryptographically secure random generators",
            "B305": "Use cryptographically secure random generators",
            "B306": "Use mkstemp() or NamedTemporaryFile() instead",
            "B307": "Use subprocess with shell=False",
            "B308": "Use defusedxml or disable XML entity processing",
            "B309": "Use defusedxml or disable XML entity processing",
            "B310": "Validate URLs and use allow-lists for permitted schemes",
            "B311": "Use secrets.SystemRandom() for cryptographic purposes",
            "B312": "Use secrets.token_urlsafe() or similar secure methods",
            "B313": "Use defusedxml or disable XML entity processing",
            "B314": "Use defusedxml or disable XML entity processing",
            "B315": "Use defusedxml or disable XML entity processing",
            "B316": "Use defusedxml or disable XML entity processing",
            "B317": "Use defusedxml or disable XML entity processing",
            "B318": "Use defusedxml or disable XML entity processing",
            "B319": "Use defusedxml or disable XML entity processing",
            "B320": "Use defusedxml or disable XML entity processing",
            "B321": "Use parameterized queries to prevent FTP injection",
            "B322": "Validate input and use parameterized queries",
            "B323": "Use urllib.parse.quote() to encode URLs properly",
            "B324": "Use hashlib with secure algorithms (SHA-256, SHA-3)",
            "B325": "Use mkstemp() or NamedTemporaryFile() instead",
            "B401": "Import and use modules securely",
            "B402": "Import and use modules securely",
            "B403": "Import and use modules securely",
            "B404": "Import and use modules securely",
            "B405": "Import and use modules securely",
            "B406": "Import and use modules securely",
            "B407": "Import and use modules securely",
            "B408": "Import and use modules securely",
            "B409": "Import and use modules securely",
            "B410": "Import and use modules securely",
            "B411": "Import and use modules securely",
            "B412": "Import and use modules securely",
            "B413": "Import and use modules securely",
            "B501": "Use HTTPS URLs and validate certificates",
            "B502": "Use HTTPS URLs and validate certificates",
            "B503": "Use HTTPS URLs and validate certificates",
            "B504": "Use HTTPS URLs and validate certificates",
            "B505": "Use cryptographically secure random generators",
            "B506": "Use HTTPS URLs and validate certificates",
            "B507": "Use parameterized queries to prevent SSH injection",
            "B601": "Use parameterized queries to prevent shell injection",
            "B602": "Use subprocess with shell=False",
            "B603": "Use subprocess with shell=False",
            "B604": "Use subprocess with shell=False",
            "B605": "Use subprocess with shell=False",
            "B606": "Use subprocess with shell=False",
            "B607": "Use subprocess with shell=False",
            "B608": "Use parameterized queries to prevent SQL injection",
            "B609": "Use subprocess with shell=False",
            "B610": "Use subprocess with shell=False",
            "B611": "Use subprocess with shell=False",
            "B701": "Use Jinja2 with autoescape enabled",
            "B702": "Use Jinja2 with autoescape enabled",
            "B703": "Use Jinja2 with autoescape enabled"
        }
        
        return recommendations.get(test_id, "Review the code and follow security best practices")


class TrivyScanner(BaseScannerService):
    """Trivy vulnerability scanner for dependencies and container images"""
    
    def __init__(self, config: TrivyConfig):
        super().__init__(config)
    
    async def scan(self, repo_path: str) -> List[DependencyVulnerability]:
        """Run Trivy scan on the repository"""
        try:
            # Build Trivy command - try local executable first, then system PATH
            import os
            trivy_exe = None
            
            # Check for local trivy executable
            local_trivy = os.path.join(os.path.dirname(__file__), "..", "..", "trivy", "trivy.exe")
            if os.path.exists(local_trivy):
                trivy_exe = local_trivy
            else:
                trivy_exe = "trivy"  # Try system PATH
            
            cmd = [
                trivy_exe,
                "fs",  # Filesystem scan
                "--format", self.config.format,
                "--timeout", self.config.timeout,
                "--severity", ",".join(self.config.severity_levels),
            ]
            
            # Add skip directories
            for skip_dir in self.config.skip_dirs:
                cmd.extend(["--skip-dirs", skip_dir])
            
            # Add the repository path
            cmd.append(repo_path)
            
            # Run Trivy
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                # Check if it's just "no vulnerabilities found"
                if "no vulnerabilities found" in stderr.decode().lower():
                    return []
                raise RuntimeError(f"Trivy scan failed: {stderr.decode()}")
            
            raw_results = stdout.decode()
            return self.parse_results(raw_results)
            
        except FileNotFoundError:
            raise RuntimeError("Trivy is not installed. Please install Trivy to use dependency scanning.")
        except Exception as e:
            raise RuntimeError(f"Trivy scan error: {str(e)}")
    
    def parse_results(self, raw_results: str) -> List[DependencyVulnerability]:
        """Parse Trivy JSON output into DependencyVulnerability objects"""
        try:
            if not raw_results.strip():
                return []
            
            data = json.loads(raw_results)
            vulnerabilities = []
            
            # Parse Trivy results
            results = data.get("Results", [])
            
            for result in results:
                target = result.get("Target", "unknown")
                vulns = result.get("Vulnerabilities", [])
                
                for vuln in vulns:
                    # Map Trivy severity to our standard levels
                    severity_map = {
                        "UNKNOWN": "low",
                        "LOW": "low",
                        "MEDIUM": "medium",
                        "HIGH": "high",
                        "CRITICAL": "critical"
                    }
                    
                    vulnerability = DependencyVulnerability(
                        tool="trivy",
                        file=target,
                        severity=severity_map.get(vuln.get("Severity", "UNKNOWN"), "low"),
                        title=vuln.get("Title", vuln.get("VulnerabilityID", "Unknown vulnerability")),
                        description=vuln.get("Description", "No description available"),
                        recommendation=self._get_trivy_recommendation(vuln),
                        cve_id=vuln.get("VulnerabilityID"),
                        package_name=vuln.get("PkgName", "unknown"),
                        installed_version=vuln.get("InstalledVersion", "unknown"),
                        fixed_version=vuln.get("FixedVersion"),
                        cve_score=self._parse_cvss_score(vuln.get("CVSS"))
                    )
                    
                    vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Trivy results: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing Trivy results: {str(e)}")
    
    def _get_trivy_recommendation(self, vuln: Dict[str, Any]) -> str:
        """Get fix recommendation for Trivy vulnerability"""
        fixed_version = vuln.get("FixedVersion")
        package_name = vuln.get("PkgName", "the package")
        
        if fixed_version:
            return f"Update {package_name} to version {fixed_version} or later"
        else:
            return f"Review {package_name} for security updates or consider alternative packages"
    
    def _parse_cvss_score(self, cvss_data: Optional[Dict[str, Any]]) -> Optional[float]:
        """Parse CVSS score from Trivy data"""
        if not cvss_data:
            return None
        
        # Try to get CVSS v3 score first, then v2
        for version in ["v3", "v2"]:
            version_data = cvss_data.get(version)
            if version_data and "Score" in version_data:
                return float(version_data["Score"])
        
        return None


class SecretScanner(BaseScannerService):
    """Secret detection scanner using detect-secrets"""
    
    def __init__(self, config: SecretScannerConfig):
        super().__init__(config)
    
    async def scan(self, repo_path: str) -> List[SecretFinding]:
        """Run secret detection scan on the repository"""
        try:
            # Create a temporary baseline file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as baseline_file:
                baseline_path = baseline_file.name
            
            try:
                # Run detect-secrets scan directly to stdout
                scan_cmd = [
                    "python", "-m", "detect_secrets",
                    "scan",
                    "--force-use-all-plugins",
                    "--all-files",  # Scan all files, not just git-tracked ones
                    repo_path
                ]
                
                # Run detect-secrets scan
                process = await asyncio.create_subprocess_exec(
                    *scan_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=repo_path
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    raise RuntimeError(f"detect-secrets scan failed: {stderr.decode()}")
                
                # Parse the stdout directly
                raw_results = stdout.decode()
                

                
                return self.parse_results(raw_results)
                
            finally:
                # Clean up temporary baseline file
                if os.path.exists(baseline_path):
                    os.unlink(baseline_path)
                    
        except FileNotFoundError:
            raise RuntimeError("detect-secrets is not installed. Please install detect-secrets to use secret scanning.")
        except Exception as e:
            raise RuntimeError(f"Secret scan error: {str(e)}")
    
    def parse_results(self, raw_results: str) -> List[SecretFinding]:
        """Parse detect-secrets JSON output into SecretFinding objects"""
        try:
            if not raw_results.strip():
                return []
            
            data = json.loads(raw_results)
            findings = []
            
            # Parse detect-secrets results (new format)
            results = data.get("results", {})
            
            for file_path, secrets in results.items():
                for secret in secrets:
                    # Get the secret type from the new format
                    secret_type = secret.get("type", "Unknown Secret")
                    
                    # Determine severity based on secret type
                    severity = self._determine_secret_severity_by_type(secret_type)
                    
                    finding = SecretFinding(
                        tool="detect-secrets",
                        file=file_path,
                        line=secret.get("line_number"),
                        severity=severity,
                        title=f"{secret_type} detected",
                        description=f"Potential {secret_type.lower()} found in code",
                        recommendation=self._get_secret_recommendation_by_type(secret_type),
                        secret_type=secret_type,
                        entropy=None,  # New format doesn't include entropy in results
                        confidence="medium"  # detect-secrets doesn't provide confidence, so we use medium
                    )
                    
                    findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse detect-secrets results: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing detect-secrets results: {str(e)}")
    
    def _determine_secret_severity(self, plugin_name: str, entropy: Optional[float]) -> str:
        """Determine severity based on secret type and entropy (legacy method)"""
        # High-risk secret types
        high_risk_types = {
            "AWSKeyDetector",
            "GitHubTokenDetector", 
            "PrivateKeyDetector",
            "JwtTokenDetector"
        }
        
        # Medium-risk secret types
        medium_risk_types = {
            "ArtifactoryDetector",
            "BasicAuthDetector",
            "SlackDetector",
            "KeywordDetector"
        }
        
        if plugin_name in high_risk_types:
            return "high"
        elif plugin_name in medium_risk_types:
            return "medium"
        elif entropy and entropy > 6.0:
            return "medium"
        else:
            return "low"
    
    def _determine_secret_severity_by_type(self, secret_type: str) -> str:
        """Determine severity based on secret type from new detect-secrets format"""
        # High-risk secret types
        high_risk_types = {
            "AWS Access Key",
            "GitHub Token",
            "Private Key",
            "JWT Token",
            "OpenAI API Key"
        }
        
        # Medium-risk secret types  
        medium_risk_types = {
            "Artifactory Token",
            "Basic Auth",
            "Slack Token",
            "Secret Keyword",
            "Azure Storage Key",
            "Discord Bot Token"
        }
        
        if secret_type in high_risk_types:
            return "high"
        elif secret_type in medium_risk_types:
            return "medium"
        else:
            return "low"
    
    def _get_secret_recommendation(self, plugin_name: str) -> str:
        """Get fix recommendation based on secret type (legacy method)"""
        recommendations = {
            "ArtifactoryDetector": "Remove hardcoded Artifactory tokens and use environment variables or secure credential storage",
            "AWSKeyDetector": "Remove AWS access keys from code and use IAM roles, environment variables, or AWS credential files",
            "Base64HighEntropyString": "Review high-entropy strings and move secrets to environment variables or secure storage",
            "BasicAuthDetector": "Remove hardcoded credentials and use secure authentication mechanisms",
            "GitHubTokenDetector": "Remove GitHub tokens from code and use environment variables or GitHub secrets",
            "HexHighEntropyString": "Review high-entropy strings and move secrets to environment variables or secure storage",
            "JwtTokenDetector": "Remove hardcoded JWT tokens and generate them dynamically or use secure storage",
            "KeywordDetector": "Remove hardcoded secrets and use environment variables or secure credential storage",
            "PrivateKeyDetector": "Remove private keys from code and use secure key management systems",
            "SlackDetector": "Remove Slack tokens from code and use environment variables or secure credential storage"
        }
        
        return recommendations.get(plugin_name, "Remove hardcoded secrets and use environment variables or secure credential storage")
    
    def _get_secret_recommendation_by_type(self, secret_type: str) -> str:
        """Get fix recommendation based on secret type from new detect-secrets format"""
        recommendations = {
            "AWS Access Key": "Remove AWS access keys from code and use IAM roles, environment variables, or AWS credential files",
            "GitHub Token": "Remove GitHub tokens from code and use environment variables or GitHub secrets",
            "Private Key": "Remove private keys from code and use secure key management systems",
            "JWT Token": "Remove hardcoded JWT tokens and generate them dynamically or use secure storage",
            "Secret Keyword": "Remove hardcoded secrets and use environment variables or secure credential storage",
            "OpenAI API Key": "Remove API keys from code and use environment variables or secure credential storage",
            "Artifactory Token": "Remove hardcoded Artifactory tokens and use environment variables or secure credential storage",
            "Basic Auth": "Remove hardcoded credentials and use secure authentication mechanisms",
            "Slack Token": "Remove Slack tokens from code and use environment variables or secure credential storage",
            "Azure Storage Key": "Remove Azure storage keys from code and use environment variables or Azure Key Vault",
            "Discord Bot Token": "Remove Discord bot tokens from code and use environment variables or secure credential storage"
        }
        
        return recommendations.get(secret_type, "Remove hardcoded secrets and use environment variables or secure credential storage")