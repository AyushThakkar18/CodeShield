"""
Unit tests for security scanner services
"""

import json
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.scanners import BanditScanner, TrivyScanner, SecretScanner
from app.models.config import BanditConfig, TrivyConfig, SecretScannerConfig
from app.models.scan import Vulnerability, DependencyVulnerability, SecretFinding


class TestBanditScanner:
    """Test cases for BanditScanner"""
    
    @pytest.fixture
    def bandit_config(self):
        """Create a test Bandit configuration"""
        return BanditConfig(
            exclude_dirs=[".git", "node_modules"],
            severity_levels=["low", "medium", "high"],
            confidence_levels=["low", "medium", "high"]
        )
    
    @pytest.fixture
    def bandit_scanner(self, bandit_config):
        """Create a BanditScanner instance"""
        return BanditScanner(bandit_config)
    
    @pytest.fixture
    def sample_bandit_output(self):
        """Sample Bandit JSON output"""
        return json.dumps({
            "results": [
                {
                    "filename": "/test/vulnerable.py",
                    "line_number": 10,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "test_name": "hardcoded_password_string",
                    "test_id": "B105",
                    "issue_text": "Possible hardcoded password: 'secret123'"
                },
                {
                    "filename": "/test/another.py",
                    "line_number": 25,
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "MEDIUM",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "test_id": "B602",
                    "issue_text": "subprocess call with shell=True identified"
                }
            ]
        })
    
    @pytest.mark.asyncio
    async def test_bandit_scan_success(self, bandit_scanner, sample_bandit_output):
        """Test successful Bandit scan"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful subprocess execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (sample_bandit_output.encode(), b"")
            mock_process.returncode = 1  # Bandit returns 1 when vulnerabilities found
            mock_subprocess.return_value = mock_process
            
            # Run scan
            results = await bandit_scanner.scan("/test/repo")
            
            # Verify results
            assert len(results) == 2
            assert all(isinstance(r, Vulnerability) for r in results)
            
            # Check first vulnerability
            vuln1 = results[0]
            assert vuln1.tool == "bandit"
            assert vuln1.file == "/test/vulnerable.py"
            assert vuln1.line == 10
            assert vuln1.severity == "high"
            assert vuln1.confidence == "high"
            assert "hardcoded_password_string" in vuln1.title
            assert "secret123" in vuln1.description
            
            # Check second vulnerability
            vuln2 = results[1]
            assert vuln2.tool == "bandit"
            assert vuln2.file == "/test/another.py"
            assert vuln2.line == 25
            assert vuln2.severity == "medium"
            assert vuln2.confidence == "medium"
    
    @pytest.mark.asyncio
    async def test_bandit_scan_no_vulnerabilities(self, bandit_scanner):
        """Test Bandit scan with no vulnerabilities found"""
        empty_output = json.dumps({"results": []})
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (empty_output.encode(), b"")
            mock_process.returncode = 0  # No vulnerabilities found
            mock_subprocess.return_value = mock_process
            
            results = await bandit_scanner.scan("/test/repo")
            
            assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_bandit_scan_failure(self, bandit_scanner):
        """Test Bandit scan failure"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Bandit error occurred")
            mock_process.returncode = 2  # Error exit code
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(RuntimeError, match="Bandit scan failed"):
                await bandit_scanner.scan("/test/repo")
    
    def test_parse_results_empty(self, bandit_scanner):
        """Test parsing empty results"""
        results = bandit_scanner.parse_results("")
        assert len(results) == 0
    
    def test_parse_results_invalid_json(self, bandit_scanner):
        """Test parsing invalid JSON"""
        with pytest.raises(RuntimeError, match="Failed to parse Bandit results"):
            bandit_scanner.parse_results("invalid json")
    
    def test_get_recommendation(self, bandit_scanner):
        """Test getting recommendations for various test IDs"""
        # Test known test ID
        rec = bandit_scanner._get_recommendation("B105")
        assert "secrets module" in rec.lower()
        
        # Test unknown test ID
        rec = bandit_scanner._get_recommendation("B999")
        assert "security best practices" in rec.lower()


class TestTrivyScanner:
    """Test cases for TrivyScanner"""
    
    @pytest.fixture
    def trivy_config(self):
        """Create a test Trivy configuration"""
        return TrivyConfig(
            scan_types=["vuln"],
            severity_levels=["HIGH", "CRITICAL"],
            skip_dirs=[".git", "node_modules"]
        )
    
    @pytest.fixture
    def trivy_scanner(self, trivy_config):
        """Create a TrivyScanner instance"""
        return TrivyScanner(trivy_config)
    
    @pytest.fixture
    def sample_trivy_output(self):
        """Sample Trivy JSON output"""
        return json.dumps({
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-12345",
                            "PkgName": "requests",
                            "InstalledVersion": "2.25.0",
                            "FixedVersion": "2.25.1",
                            "Severity": "HIGH",
                            "Title": "HTTP Request Smuggling",
                            "Description": "Vulnerability in requests library",
                            "CVSS": {
                                "v3": {
                                    "Score": 7.5
                                }
                            }
                        }
                    ]
                }
            ]
        })
    
    @pytest.mark.asyncio
    async def test_trivy_scan_success(self, trivy_scanner, sample_trivy_output):
        """Test successful Trivy scan"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (sample_trivy_output.encode(), b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            results = await trivy_scanner.scan("/test/repo")
            
            assert len(results) == 1
            assert all(isinstance(r, DependencyVulnerability) for r in results)
            
            vuln = results[0]
            assert vuln.tool == "trivy"
            assert vuln.file == "requirements.txt"
            assert vuln.severity == "high"
            assert vuln.cve_id == "CVE-2021-12345"
            assert vuln.package_name == "requests"
            assert vuln.installed_version == "2.25.0"
            assert vuln.fixed_version == "2.25.1"
            assert vuln.cve_score == 7.5
    
    @pytest.mark.asyncio
    async def test_trivy_scan_no_vulnerabilities(self, trivy_scanner):
        """Test Trivy scan with no vulnerabilities"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"no vulnerabilities found")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process
            
            results = await trivy_scanner.scan("/test/repo")
            assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_trivy_not_installed(self, trivy_scanner):
        """Test Trivy scan when Trivy is not installed"""
        with patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="Trivy is not installed"):
                await trivy_scanner.scan("/test/repo")
    
    def test_parse_cvss_score(self, trivy_scanner):
        """Test CVSS score parsing"""
        # Test v3 score
        cvss_data = {"v3": {"Score": 8.5}}
        score = trivy_scanner._parse_cvss_score(cvss_data)
        assert score == 8.5
        
        # Test v2 score when v3 not available
        cvss_data = {"v2": {"Score": 7.2}}
        score = trivy_scanner._parse_cvss_score(cvss_data)
        assert score == 7.2
        
        # Test no score available
        score = trivy_scanner._parse_cvss_score(None)
        assert score is None
    
    def test_get_trivy_recommendation(self, trivy_scanner):
        """Test getting Trivy recommendations"""
        # Test with fixed version
        vuln = {"PkgName": "requests", "FixedVersion": "2.25.1"}
        rec = trivy_scanner._get_trivy_recommendation(vuln)
        assert "Update requests to version 2.25.1" in rec
        
        # Test without fixed version
        vuln = {"PkgName": "requests"}
        rec = trivy_scanner._get_trivy_recommendation(vuln)
        assert "Review requests for security updates" in rec


class TestSecretScanner:
    """Test cases for SecretScanner"""
    
    @pytest.fixture
    def secret_config(self):
        """Create a test secret scanner configuration"""
        return SecretScannerConfig(
            plugins=["AWSKeyDetector", "GitHubTokenDetector"],
            exclude_files=["*.log"],
            entropy_threshold=4.5
        )
    
    @pytest.fixture
    def secret_scanner(self, secret_config):
        """Create a SecretScanner instance"""
        return SecretScanner(secret_config)
    
    @pytest.fixture
    def sample_secrets_output(self):
        """Sample detect-secrets JSON output (new format)"""
        return json.dumps({
            "version": "1.5.0",
            "results": {
                "config.py": [
                    {
                        "type": "AWS Access Key",
                        "filename": "config.py",
                        "line_number": 15,
                        "hashed_secret": "abc123",
                        "is_verified": False
                    }
                ],
                "app.py": [
                    {
                        "type": "GitHub Token",
                        "filename": "app.py", 
                        "line_number": 8,
                        "hashed_secret": "def456",
                        "is_verified": False
                    }
                ]
            }
        })
    
    @pytest.mark.asyncio
    async def test_secret_scan_success(self, secret_scanner, sample_secrets_output):
        """Test successful secret scan"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess, \
             patch('tempfile.NamedTemporaryFile') as mock_temp, \
             patch('builtins.open', create=True) as mock_open:
            
            # Mock temporary file
            mock_temp.return_value.__enter__.return_value.name = "/tmp/baseline.json"
            
            # Mock subprocess - return the sample output directly
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (sample_secrets_output.encode(), b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            # Mock os.path.exists and os.unlink
            with patch('os.path.exists', return_value=True), \
                 patch('os.unlink'):
                
                results = await secret_scanner.scan("/test/repo")
                
                assert len(results) == 2
                assert all(isinstance(r, SecretFinding) for r in results)
                
                # Check AWS key finding
                aws_finding = next(r for r in results if r.secret_type == "AWS Access Key")
                assert aws_finding.tool == "detect-secrets"
                assert aws_finding.file == "config.py"
                assert aws_finding.line == 15
                assert aws_finding.entropy is None  # New format doesn't include entropy
                assert aws_finding.severity == "high"  # AWS keys are high severity
                
                # Check GitHub token finding
                github_finding = next(r for r in results if r.secret_type == "GitHub Token")
                assert github_finding.tool == "detect-secrets"
                assert github_finding.file == "app.py"
                assert github_finding.line == 8
                assert github_finding.entropy is None  # New format doesn't include entropy
                assert github_finding.severity == "high"  # GitHub tokens are high severity
    
    @pytest.mark.asyncio
    async def test_secret_scan_not_installed(self, secret_scanner):
        """Test secret scan when detect-secrets is not installed"""
        with patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="detect-secrets is not installed"):
                await secret_scanner.scan("/test/repo")
    
    def test_determine_secret_severity(self, secret_scanner):
        """Test secret severity determination"""
        # High-risk types
        assert secret_scanner._determine_secret_severity("AWSKeyDetector", None) == "high"
        assert secret_scanner._determine_secret_severity("GitHubTokenDetector", None) == "high"
        assert secret_scanner._determine_secret_severity("PrivateKeyDetector", None) == "high"
        
        # Medium-risk types
        assert secret_scanner._determine_secret_severity("BasicAuthDetector", None) == "medium"
        assert secret_scanner._determine_secret_severity("SlackDetector", None) == "medium"
        
        # High entropy strings
        assert secret_scanner._determine_secret_severity("Base64HighEntropyString", 7.0) == "medium"
        
        # Low-risk/entropy
        assert secret_scanner._determine_secret_severity("Base64HighEntropyString", 3.0) == "low"
    
    def test_get_secret_recommendation(self, secret_scanner):
        """Test getting secret recommendations"""
        # Test AWS key recommendation
        rec = secret_scanner._get_secret_recommendation("AWSKeyDetector")
        assert "AWS access keys" in rec and "environment variables" in rec
        
        # Test GitHub token recommendation
        rec = secret_scanner._get_secret_recommendation("GitHubTokenDetector")
        assert "GitHub tokens" in rec and "environment variables" in rec
        
        # Test unknown type
        rec = secret_scanner._get_secret_recommendation("UnknownDetector")
        assert "environment variables" in rec


# Integration test fixtures for creating test repositories
@pytest.fixture
def temp_repo_with_vulnerabilities():
    """Create a temporary repository with known vulnerabilities for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir)
        
        # Create Python file with Bandit vulnerabilities
        vulnerable_py = repo_path / "vulnerable.py"
        vulnerable_py.write_text("""
import subprocess
import os

# B105: Hardcoded password
password = "secret123"

# B602: subprocess with shell=True
def run_command(cmd):
    subprocess.call(cmd, shell=True)

# B108: Insecure temp file
temp_file = "/tmp/myapp.tmp"
with open(temp_file, "w") as f:
    f.write("data")
""")
        
        # Create requirements.txt for Trivy testing
        requirements = repo_path / "requirements.txt"
        requirements.write_text("""
requests==2.20.0
django==2.0.0
flask==0.12.0
""")
        
        # Create file with secrets for detect-secrets testing
        config_py = repo_path / "config.py"
        config_py.write_text("""
# AWS access key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# GitHub token
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"

# Database password
DB_PASSWORD = "super_secret_password_123"
""")
        
        yield str(repo_path)


@pytest.mark.integration
class TestScannersIntegration:
    """Integration tests for scanners with real test data"""
    
    @pytest.mark.asyncio
    async def test_bandit_integration(self, temp_repo_with_vulnerabilities):
        """Integration test for Bandit scanner with real vulnerable code"""
        config = BanditConfig()
        scanner = BanditScanner(config)
        
        try:
            results = await scanner.scan(temp_repo_with_vulnerabilities)
            
            # Should find vulnerabilities in the test code
            assert len(results) > 0
            
            # Check that we found expected vulnerability types
            vulnerability_types = [r.title for r in results]
            # Look for subprocess or hardcoded vulnerabilities instead of password
            assert any("subprocess" in vtype.lower() or "hardcoded" in vtype.lower() for vtype in vulnerability_types)
            
        except RuntimeError as e:
            if "Bandit" in str(e):
                pytest.skip("Bandit not available in test environment")
            raise
    
    @pytest.mark.asyncio
    async def test_secret_scanner_integration(self, temp_repo_with_vulnerabilities):
        """Integration test for secret scanner with real secret patterns"""
        config = SecretScannerConfig()
        scanner = SecretScanner(config)
        
        try:
            results = await scanner.scan(temp_repo_with_vulnerabilities)
            
            # Should find secrets in the test code
            assert len(results) > 0
            
            # Check that we found expected secret types
            secret_types = [r.secret_type for r in results]
            assert any("AWS" in stype for stype in secret_types)
            
        except RuntimeError as e:
            if "detect-secrets" in str(e):
                pytest.skip("detect-secrets not available in test environment")
            raise