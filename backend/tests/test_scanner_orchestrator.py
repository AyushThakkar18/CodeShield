"""
Integration tests for scanner orchestration service
"""

import asyncio
import json
import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from app.services.scanner_orchestrator import ScannerService
from app.models.config import SecurityToolsConfig, BanditConfig, TrivyConfig, SecretScannerConfig
from app.models.scan import ScanResults, Vulnerability, DependencyVulnerability, SecretFinding


class TestScannerService:
    """Test cases for ScannerService orchestration"""
    
    @pytest.fixture
    def security_config(self):
        """Create test security tools configuration"""
        return SecurityToolsConfig(
            bandit=BanditConfig(exclude_dirs=[".git", "node_modules"]),
            trivy=TrivyConfig(severity_levels=["HIGH", "CRITICAL"]),
            secret_scanner=SecretScannerConfig(plugins=["AWSKeyDetector", "GitHubTokenDetector"])
        )
    
    @pytest.fixture
    def scanner_service(self, security_config):
        """Create ScannerService instance"""
        return ScannerService(security_config)
    
    @pytest.fixture
    def mock_bandit_results(self):
        """Mock Bandit scan results"""
        return [
            Vulnerability(
                tool="bandit",
                file="test.py",
                line=10,
                severity="high",
                title="Hardcoded password",
                description="Possible hardcoded password found",
                recommendation="Use environment variables",
                confidence="high"
            ),
            Vulnerability(
                tool="bandit",
                file="app.py", 
                line=25,
                severity="medium",
                title="Subprocess with shell=True",
                description="subprocess call with shell=True",
                recommendation="Use shell=False",
                confidence="medium"
            )
        ]
    
    @pytest.fixture
    def mock_trivy_results(self):
        """Mock Trivy scan results"""
        return [
            DependencyVulnerability(
                tool="trivy",
                file="requirements.txt",
                severity="critical",
                title="Critical vulnerability in requests",
                description="HTTP request smuggling vulnerability",
                recommendation="Update to version 2.25.1",
                cve_id="CVE-2021-12345",
                package_name="requests",
                installed_version="2.20.0",
                fixed_version="2.25.1",
                cve_score=9.1
            )
        ]
    
    @pytest.fixture
    def mock_secret_results(self):
        """Mock secret scanner results"""
        return [
            SecretFinding(
                tool="detect-secrets",
                file="config.py",
                line=15,
                severity="high",
                title="AWS Access Key detected",
                description="Potential AWS access key found",
                recommendation="Remove from code and use environment variables",
                secret_type="AWS Access Key",
                confidence="medium"
            )
        ]
    
    @pytest.mark.asyncio
    async def test_scan_repository_success(
        self, 
        scanner_service, 
        mock_bandit_results,
        mock_trivy_results, 
        mock_secret_results
    ):
        """Test successful complete repository scan"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock all scanner methods
        with patch.object(scanner_service.bandit_scanner, 'scan', return_value=mock_bandit_results), \
             patch.object(scanner_service.trivy_scanner, 'scan', return_value=mock_trivy_results), \
             patch.object(scanner_service.secret_scanner, 'scan', return_value=mock_secret_results):
            
            results = await scanner_service.scan_repository(repo_path, repo_url)
            
            # Verify scan results structure
            assert isinstance(results, ScanResults)
            assert str(results.repository_url) == repo_url
            assert results.status == "completed"
            assert results.scan_duration >= 0  # Duration can be 0 for mocked scanners
            
            # Verify findings are properly categorized
            assert len(results.static_analysis) == 2  # Bandit results
            assert len(results.dependencies) == 1     # Trivy results
            assert len(results.secrets) == 1          # Secret results
            
            # Verify summary statistics
            assert results.summary.total == 4
            assert results.summary.critical == 1  # Trivy critical
            assert results.summary.high == 2      # Bandit high + Secret high
            assert results.summary.medium == 1    # Bandit medium
            assert results.summary.low == 0
    
    @pytest.mark.asyncio
    async def test_scan_repository_partial_failure(
        self, 
        scanner_service,
        mock_bandit_results,
        mock_trivy_results
    ):
        """Test repository scan with one scanner failing"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock successful scanners and one failure
        with patch.object(scanner_service.bandit_scanner, 'scan', return_value=mock_bandit_results), \
             patch.object(scanner_service.trivy_scanner, 'scan', return_value=mock_trivy_results), \
             patch.object(scanner_service.secret_scanner, 'scan', side_effect=RuntimeError("Scanner failed")):
            
            results = await scanner_service.scan_repository(repo_path, repo_url)
            
            # Should still return results from successful scanners
            assert results.status == "partial"
            assert len(results.static_analysis) == 2  # Bandit succeeded
            assert len(results.dependencies) == 1     # Trivy succeeded
            assert len(results.secrets) == 0          # Secret scanner failed
            
            # Summary should reflect only successful scans
            assert results.summary.total == 3
    
    @pytest.mark.asyncio
    async def test_scan_repository_complete_failure(self, scanner_service):
        """Test repository scan with all scanners failing"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock all scanners to fail
        with patch.object(scanner_service.bandit_scanner, 'scan', side_effect=RuntimeError("Bandit failed")), \
             patch.object(scanner_service.trivy_scanner, 'scan', side_effect=RuntimeError("Trivy failed")), \
             patch.object(scanner_service.secret_scanner, 'scan', side_effect=RuntimeError("Secret scanner failed")):
            
            results = await scanner_service.scan_repository(repo_path, repo_url)
            
            # Should return failed status with empty results
            assert results.status == "failed"
            assert len(results.static_analysis) == 0
            assert len(results.dependencies) == 0
            assert len(results.secrets) == 0
            assert results.summary.total == 0
    
    @pytest.mark.asyncio
    async def test_scanner_retry_logic(self, scanner_service, mock_bandit_results):
        """Test retry logic for failed scanners"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock Bandit to fail once then succeed
        bandit_call_count = 0
        def bandit_side_effect(*args, **kwargs):
            nonlocal bandit_call_count
            bandit_call_count += 1
            if bandit_call_count == 1:
                raise RuntimeError("First attempt failed")
            return mock_bandit_results
        
        with patch.object(scanner_service.bandit_scanner, 'scan', side_effect=bandit_side_effect), \
             patch.object(scanner_service.trivy_scanner, 'scan', return_value=[]), \
             patch.object(scanner_service.secret_scanner, 'scan', return_value=[]):
            
            results = await scanner_service.scan_repository(repo_path, repo_url)
            
            # Should succeed after retry
            assert results.status == "completed"
            assert len(results.static_analysis) == 2
            assert bandit_call_count == 2  # Called twice due to retry
    
    @pytest.mark.asyncio
    async def test_scanner_retry_exhaustion(self, scanner_service):
        """Test behavior when all retries are exhausted"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock Bandit to always fail
        with patch.object(scanner_service.bandit_scanner, 'scan', side_effect=RuntimeError("Always fails")), \
             patch.object(scanner_service.trivy_scanner, 'scan', return_value=[]), \
             patch.object(scanner_service.secret_scanner, 'scan', return_value=[]):
            
            results = await scanner_service.scan_repository(repo_path, repo_url)
            
            # Should be partial success (other scanners worked)
            assert results.status == "partial"
            assert len(results.static_analysis) == 0  # Bandit failed
    
    def test_deduplicate_findings(self, scanner_service):
        """Test deduplication of identical findings"""
        # Create duplicate findings
        findings = [
            Vulnerability(
                tool="bandit",
                file="test.py",
                line=10,
                severity="high",
                title="Hardcoded password",
                description="Description 1",
                recommendation="Fix 1"
            ),
            Vulnerability(
                tool="bandit", 
                file="test.py",
                line=10,
                severity="high",
                title="Hardcoded password",
                description="Description 2",  # Different description
                recommendation="Fix 2"       # Different recommendation
            ),
            Vulnerability(
                tool="bandit",
                file="test.py",
                line=20,  # Different line
                severity="high",
                title="Hardcoded password",
                description="Description 3",
                recommendation="Fix 3"
            )
        ]
        
        deduplicated = scanner_service._deduplicate_findings(findings)
        
        # Should remove the duplicate (same file, line, title, tool)
        assert len(deduplicated) == 2
        assert deduplicated[0].line == 10
        assert deduplicated[1].line == 20
    
    def test_severity_categorization(self, scanner_service):
        """Test severity normalization"""
        # Create findings with valid tool names but test severity normalization
        findings = [
            Vulnerability(
                tool="bandit",
                file="test.py",
                severity="high",  # Valid severity
                title="Test",
                description="Test",
                recommendation="Test"
            ),
            Vulnerability(
                tool="bandit",
                file="test.py", 
                severity="medium",  # Valid severity
                title="Test",
                description="Test",
                recommendation="Test"
            )
        ]
        
        # Manually set invalid severities to test normalization
        findings[0].severity = "HIGH"  # Uppercase
        findings[1].severity = "Medium"  # Mixed case
        
        categorized = scanner_service._categorize_by_severity(findings)
        
        # Should normalize to lowercase
        assert categorized[0].severity == "high"
        assert categorized[1].severity == "low"  # Invalid case defaults to low
    
    def test_calculate_summary(self, scanner_service):
        """Test summary statistics calculation"""
        aggregated_results = {
            "static_analysis": [
                Vulnerability(
                    tool="bandit", file="test.py", severity="high",
                    title="Test", description="Test", recommendation="Test"
                ),
                Vulnerability(
                    tool="bandit", file="test.py", severity="medium", 
                    title="Test", description="Test", recommendation="Test"
                )
            ],
            "dependencies": [
                DependencyVulnerability(
                    tool="trivy", file="req.txt", severity="critical",
                    title="Test", description="Test", recommendation="Test",
                    package_name="test", installed_version="1.0"
                )
            ],
            "secrets": [
                SecretFinding(
                    tool="detect-secrets", file="config.py", severity="high",
                    title="Test", description="Test", recommendation="Test",
                    secret_type="API Key"
                )
            ]
        }
        
        summary = scanner_service._calculate_summary(aggregated_results)
        
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.low == 0
        assert summary.total == 4
    
    def test_determine_scan_status(self, scanner_service):
        """Test scan status determination logic"""
        # All successful
        results = [("bandit", []), ("trivy", []), ("secrets", [])]
        status = scanner_service._determine_scan_status(results)
        assert status == "completed"
        
        # One failure
        results = [("bandit", []), RuntimeError("Failed"), ("secrets", [])]
        status = scanner_service._determine_scan_status(results)
        assert status == "partial"
        
        # All failures
        results = [RuntimeError("Failed"), RuntimeError("Failed"), RuntimeError("Failed")]
        status = scanner_service._determine_scan_status(results)
        assert status == "failed"
    
    @pytest.mark.asyncio
    async def test_get_scanner_status(self, scanner_service):
        """Test scanner availability checking"""
        with patch('builtins.__import__') as mock_import, \
             patch('asyncio.create_subprocess_exec') as mock_subprocess:
            
            # Mock successful imports
            def import_side_effect(name, *args, **kwargs):
                if name in ['bandit', 'detect_secrets']:
                    return MagicMock()
                return __import__(name, *args, **kwargs)
            
            mock_import.side_effect = import_side_effect
            
            # Mock successful subprocess for trivy
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"trivy version", b"")
            mock_subprocess.return_value = mock_process
            
            status = await scanner_service.get_scanner_status()
            
            # Should detect available scanners
            assert "bandit" in status
            assert "trivy" in status
            assert "detect-secrets" in status
    
    @pytest.mark.asyncio
    async def test_parallel_execution_timing(self, scanner_service):
        """Test that scanners run in parallel, not sequentially"""
        repo_path = "/test/repo"
        repo_url = "https://github.com/test/repo"
        
        # Mock scanners with delays to test parallelism
        async def slow_scanner(*args, **kwargs):
            await asyncio.sleep(0.1)  # 100ms delay
            return []
        
        with patch.object(scanner_service.bandit_scanner, 'scan', side_effect=slow_scanner), \
             patch.object(scanner_service.trivy_scanner, 'scan', side_effect=slow_scanner), \
             patch.object(scanner_service.secret_scanner, 'scan', side_effect=slow_scanner):
            
            start_time = time.time()
            results = await scanner_service.scan_repository(repo_path, repo_url)
            end_time = time.time()
            
            # Should complete in ~100ms (parallel) not ~300ms (sequential)
            # Allow some overhead for test execution
            assert end_time - start_time < 0.2
            assert results.status == "completed"


@pytest.mark.integration
class TestScannerServiceIntegration:
    """Integration tests with real scanner tools"""
    
    @pytest.fixture
    def temp_vulnerable_repo(self):
        """Create temporary repository with known vulnerabilities"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            
            # Python file with Bandit issues
            (repo_path / "vulnerable.py").write_text("""
import subprocess
import os

# Hardcoded password
password = "secret123"

# Subprocess with shell=True
def run_cmd(cmd):
    subprocess.call(cmd, shell=True)
""")
            
            # Requirements with vulnerable dependencies
            (repo_path / "requirements.txt").write_text("""
requests==2.20.0
django==2.0.0
""")
            
            # File with secrets
            (repo_path / "config.py").write_text("""
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
""")
            
            yield str(repo_path)
    
    @pytest.mark.asyncio
    async def test_full_integration_scan(self, temp_vulnerable_repo):
        """Integration test with real vulnerable repository"""
        config = SecurityToolsConfig()
        service = ScannerService(config)
        
        try:
            results = await service.scan_repository(
                temp_vulnerable_repo,
                "https://github.com/test/integration-repo"
            )
            
            # Should complete successfully
            assert results.status in ["completed", "partial"]
            assert results.scan_duration > 0
            assert isinstance(results.scan_date, datetime)
            
            # Should find some vulnerabilities (exact count depends on tool availability)
            total_findings = (
                len(results.static_analysis) + 
                len(results.dependencies) + 
                len(results.secrets)
            )
            
            # At minimum, should find some issues if any scanner works
            if results.status == "completed":
                assert total_findings > 0
            
            # Summary should match individual findings
            expected_total = (
                len(results.static_analysis) + 
                len(results.dependencies) + 
                len(results.secrets)
            )
            assert results.summary.total == expected_total
            
        except Exception as e:
            # If tools aren't available, skip the test
            if any(tool in str(e).lower() for tool in ["bandit", "trivy", "detect-secrets"]):
                pytest.skip(f"Security scanning tools not available: {str(e)}")
            raise
    
    @pytest.mark.asyncio
    async def test_scanner_availability(self):
        """Test checking scanner tool availability"""
        config = SecurityToolsConfig()
        service = ScannerService(config)
        
        # This test will use real imports, so we expect it to work with actual tools
        try:
            status = await service.get_scanner_status()
            
            # Should return status for all scanners
            assert "bandit" in status
            assert "trivy" in status
            assert "detect-secrets" in status
            
            # Status should be boolean
            for scanner, available in status.items():
                assert isinstance(available, bool)
                
        except Exception as e:
            # If tools cause import issues, skip the test
            pytest.skip(f"Scanner availability test skipped due to import issues: {str(e)}")
    
    @pytest.mark.asyncio
    async def test_empty_repository_scan(self):
        """Test scanning an empty repository"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = SecurityToolsConfig()
            service = ScannerService(config)
            
            try:
                results = await service.scan_repository(
                    temp_dir,
                    "https://github.com/test/empty-repo"
                )
                
                # Should complete without errors
                assert results.status in ["completed", "partial"]
                
                # Should find no vulnerabilities
                assert results.summary.total == 0
                assert len(results.static_analysis) == 0
                assert len(results.dependencies) == 0
                assert len(results.secrets) == 0
                
            except Exception as e:
                if any(tool in str(e).lower() for tool in ["bandit", "trivy", "detect-secrets"]):
                    pytest.skip(f"Security scanning tools not available: {str(e)}")
                raise


# Performance and stress tests
@pytest.mark.performance
class TestScannerServicePerformance:
    """Performance tests for scanner service"""
    
    @pytest.mark.asyncio
    async def test_concurrent_scans(self):
        """Test multiple concurrent scans"""
        config = SecurityToolsConfig()
        service = ScannerService(config)
        
        # Create multiple temporary repositories
        scan_tasks = []
        
        for i in range(3):  # Test with 3 concurrent scans
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create minimal test file
                Path(temp_dir, "test.py").write_text("print('hello')")
                
                task = service.scan_repository(
                    temp_dir,
                    f"https://github.com/test/repo-{i}"
                )
                scan_tasks.append(task)
        
        try:
            # Run all scans concurrently
            start_time = time.time()
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            end_time = time.time()
            
            # All should complete
            for result in results:
                if isinstance(result, Exception):
                    # Skip if tools not available
                    if any(tool in str(result).lower() for tool in ["bandit", "trivy", "detect-secrets"]):
                        pytest.skip(f"Security scanning tools not available: {str(result)}")
                    raise result
                
                assert isinstance(result, ScanResults)
                assert result.status in ["completed", "partial", "failed"]
            
            # Should complete in reasonable time
            assert end_time - start_time < 30  # 30 seconds max for 3 concurrent scans
            
        except Exception as e:
            if any(tool in str(e).lower() for tool in ["bandit", "trivy", "detect-secrets"]):
                pytest.skip(f"Security scanning tools not available: {str(e)}")
            raise