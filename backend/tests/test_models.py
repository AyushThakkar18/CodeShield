"""
Unit tests for CodeShield data models
"""

import pytest
from datetime import datetime
from pydantic import ValidationError
from app.models.scan import (
    ScanRequest,
    ScanResponse,
    Vulnerability,
    DependencyVulnerability,
    SecretFinding,
    ScanSummary,
    ScanResults,
    ScanStatus,
    ErrorDetail,
    ErrorResponse
)
from app.models.config import (
    ScanConfig,
    BanditConfig,
    TrivyConfig,
    SecretScannerConfig,
    AppConfig
)


class TestScanRequest:
    """Test ScanRequest model validation"""
    
    def test_valid_github_url(self):
        """Test valid GitHub URL acceptance"""
        request = ScanRequest(repository_url="https://github.com/user/repo")
        assert str(request.repository_url) == "https://github.com/user/repo"
    
    def test_invalid_non_github_url(self):
        """Test rejection of non-GitHub URLs"""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(repository_url="https://gitlab.com/user/repo")
        assert "Only GitHub repository URLs are supported" in str(exc_info.value)
    
    def test_invalid_url_format(self):
        """Test rejection of invalid URL format"""
        with pytest.raises(ValidationError):
            ScanRequest(repository_url="not-a-url")


class TestVulnerability:
    """Test Vulnerability model validation"""
    
    def test_valid_vulnerability(self):
        """Test valid vulnerability creation"""
        vuln = Vulnerability(
            tool="bandit",
            file="test.py",
            line=42,
            severity="high",
            title="SQL Injection",
            description="Potential SQL injection vulnerability",
            recommendation="Use parameterized queries",
            cve_id="CVE-2023-1234",
            confidence="high"
        )
        assert vuln.tool == "bandit"
        assert vuln.line == 42
        assert vuln.severity == "high"
    
    def test_invalid_tool(self):
        """Test rejection of invalid tool name"""
        with pytest.raises(ValidationError):
            Vulnerability(
                tool="invalid-tool",
                file="test.py",
                severity="high",
                title="Test",
                description="Test",
                recommendation="Test"
            )
    
    def test_invalid_severity(self):
        """Test rejection of invalid severity level"""
        with pytest.raises(ValidationError):
            Vulnerability(
                tool="bandit",
                file="test.py",
                severity="invalid",
                title="Test",
                description="Test",
                recommendation="Test"
            )


class TestDependencyVulnerability:
    """Test DependencyVulnerability model validation"""
    
    def test_valid_dependency_vulnerability(self):
        """Test valid dependency vulnerability creation"""
        dep_vuln = DependencyVulnerability(
            tool="trivy",
            file="requirements.txt",
            severity="critical",
            title="Vulnerable Package",
            description="Package has known vulnerability",
            recommendation="Update to latest version",
            package_name="requests",
            installed_version="2.25.0",
            fixed_version="2.28.0",
            cve_score=9.8
        )
        assert dep_vuln.package_name == "requests"
        assert dep_vuln.cve_score == 9.8
    
    def test_invalid_cve_score(self):
        """Test rejection of invalid CVE score"""
        with pytest.raises(ValidationError):
            DependencyVulnerability(
                tool="trivy",
                file="requirements.txt",
                severity="high",
                title="Test",
                description="Test",
                recommendation="Test",
                package_name="test",
                installed_version="1.0.0",
                cve_score=15.0  # Invalid: > 10.0
            )


class TestSecretFinding:
    """Test SecretFinding model validation"""
    
    def test_valid_secret_finding(self):
        """Test valid secret finding creation"""
        secret = SecretFinding(
            tool="detect-secrets",
            file="config.py",
            line=10,
            severity="high",
            title="API Key Detected",
            description="Potential API key found",
            recommendation="Remove hardcoded secrets",
            secret_type="api_key",
            entropy=4.8,
            is_verified=True
        )
        assert secret.secret_type == "api_key"
        assert secret.entropy == 4.8
        assert secret.is_verified is True


class TestScanSummary:
    """Test ScanSummary model validation and calculation"""
    
    def test_total_calculation(self):
        """Test automatic total calculation"""
        summary = ScanSummary(
            critical=2,
            high=5,
            medium=10,
            low=3
        )
        assert summary.total == 20
    
    def test_negative_values_rejected(self):
        """Test rejection of negative values"""
        with pytest.raises(ValidationError):
            ScanSummary(critical=-1)


class TestScanResults:
    """Test ScanResults model validation"""
    
    def test_valid_scan_results(self):
        """Test valid scan results creation"""
        results = ScanResults(
            scan_id="test-123",
            repository_url="https://github.com/user/repo",
            scan_date=datetime.now(),
            summary=ScanSummary(critical=1, high=2, medium=3, low=4),
            scan_duration=120.5,
            status="completed"
        )
        assert results.scan_id == "test-123"
        assert results.summary.total == 10
        assert results.status == "completed"
    
    def test_invalid_status(self):
        """Test rejection of invalid status"""
        with pytest.raises(ValidationError):
            ScanResults(
                scan_id="test-123",
                repository_url="https://github.com/user/repo",
                scan_date=datetime.now(),
                summary=ScanSummary(),
                scan_duration=120.5,
                status="invalid-status"
            )


class TestScanStatus:
    """Test ScanStatus model validation"""
    
    def test_valid_scan_status(self):
        """Test valid scan status creation"""
        status = ScanStatus(
            scan_id="test-123",
            status="scanning",
            progress=45,
            current_operation="Running Bandit scan",
            estimated_time_remaining=60
        )
        assert status.progress == 45
        assert status.current_operation == "Running Bandit scan"
    
    def test_invalid_progress_range(self):
        """Test rejection of invalid progress values"""
        with pytest.raises(ValidationError):
            ScanStatus(
                scan_id="test-123",
                status="scanning",
                progress=150  # Invalid: > 100
            )
        
        with pytest.raises(ValidationError):
            ScanStatus(
                scan_id="test-123", 
                status="scanning",
                progress=-10  # Invalid: < 0
            )


class TestScanConfig:
    """Test ScanConfig model validation"""
    
    def test_valid_scan_config(self):
        """Test valid scan configuration"""
        config = ScanConfig(
            max_repo_size_mb=500,
            scan_timeout_minutes=10,
            temp_dir_prefix="custom_",
            cleanup_delay_minutes=15
        )
        assert config.max_repo_size_mb == 500
        assert config.temp_dir_prefix == "custom_"
    
    def test_invalid_negative_values(self):
        """Test rejection of invalid negative values"""
        with pytest.raises(ValidationError):
            ScanConfig(max_repo_size_mb=0)  # Invalid: must be >= 1


class TestBanditConfig:
    """Test BanditConfig model validation"""
    
    def test_valid_bandit_config(self):
        """Test valid Bandit configuration"""
        config = BanditConfig(
            exclude_dirs=[".git", "tests"],
            severity_levels=["medium", "high"],
            confidence_levels=["high"]
        )
        assert ".git" in config.exclude_dirs
        assert "medium" in config.severity_levels
    
    def test_invalid_severity_levels(self):
        """Test rejection of invalid severity levels"""
        with pytest.raises(ValidationError):
            BanditConfig(severity_levels=["invalid", "high"])


class TestTrivyConfig:
    """Test TrivyConfig model validation"""
    
    def test_valid_trivy_config(self):
        """Test valid Trivy configuration"""
        config = TrivyConfig(
            scan_types=["vuln", "secret"],
            severity_levels=["HIGH", "CRITICAL"]
        )
        assert "vuln" in config.scan_types
        assert "HIGH" in config.severity_levels
    
    def test_invalid_scan_types(self):
        """Test rejection of invalid scan types"""
        with pytest.raises(ValidationError):
            TrivyConfig(scan_types=["invalid", "vuln"])


class TestSecretScannerConfig:
    """Test SecretScannerConfig model validation"""
    
    def test_valid_secret_scanner_config(self):
        """Test valid secret scanner configuration"""
        config = SecretScannerConfig(
            plugins=["AWSKeyDetector", "GitHubTokenDetector"],
            entropy_threshold=5.0
        )
        assert "AWSKeyDetector" in config.plugins
        assert config.entropy_threshold == 5.0
    
    def test_invalid_entropy_threshold(self):
        """Test rejection of invalid entropy threshold"""
        with pytest.raises(ValidationError):
            SecretScannerConfig(entropy_threshold=10.0)  # Invalid: > 8.0


class TestModelSerialization:
    """Test model serialization and deserialization"""
    
    def test_vulnerability_json_serialization(self):
        """Test vulnerability JSON serialization"""
        vuln = Vulnerability(
            tool="bandit",
            file="test.py",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            recommendation="Fix it"
        )
        
        # Test serialization
        json_data = vuln.model_dump()
        assert json_data["tool"] == "bandit"
        assert json_data["severity"] == "high"
        
        # Test deserialization
        new_vuln = Vulnerability(**json_data)
        assert new_vuln.tool == vuln.tool
        assert new_vuln.severity == vuln.severity
    
    def test_scan_results_json_serialization(self):
        """Test scan results JSON serialization"""
        results = ScanResults(
            scan_id="test-123",
            repository_url="https://github.com/user/repo",
            scan_date=datetime.now(),
            summary=ScanSummary(critical=1, high=2, medium=3, low=4),
            scan_duration=120.5,
            status="completed"
        )
        
        # Test serialization
        json_data = results.model_dump()
        assert json_data["scan_id"] == "test-123"
        assert json_data["summary"]["total"] == 10
        
        # Test deserialization
        new_results = ScanResults(**json_data)
        assert new_results.scan_id == results.scan_id
        assert new_results.summary.total == results.summary.total