"""
Unit tests for ReportService
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.app.services.report import ReportService, WEASYPRINT_AVAILABLE, REPORTLAB_AVAILABLE
from backend.app.models.scan import (
    ScanResults, ScanSummary, Vulnerability, DependencyVulnerability, 
    SecretFinding
)


@pytest.fixture
def sample_scan_results():
    """Create sample scan results for testing"""
    return ScanResults(
        scan_id="test-scan-123",
        repository_url="https://github.com/test/repo",
        scan_date=datetime(2024, 1, 15, 10, 30, 0),
        summary=ScanSummary(
            critical=2,
            high=3,
            medium=5,
            low=1
        ),
        static_analysis=[
            Vulnerability(
                tool="bandit",
                file="src/app.py",
                line=42,
                severity="high",
                title="SQL Injection Risk",
                description="Potential SQL injection vulnerability",
                recommendation="Use parameterized queries",
                confidence="high"
            ),
            Vulnerability(
                tool="bandit",
                file="src/auth.py",
                line=15,
                severity="medium",
                title="Hardcoded Password",
                description="Password appears to be hardcoded",
                recommendation="Use environment variables for secrets"
            )
        ],
        dependencies=[
            DependencyVulnerability(
                tool="trivy",
                file="requirements.txt",
                severity="critical",
                title="Known CVE in requests library",
                description="requests library has known vulnerability",
                recommendation="Update to version 2.28.0 or higher",
                package_name="requests",
                installed_version="2.25.1",
                fixed_version="2.28.0",
                cve_id="CVE-2023-32681",
                cve_score=9.1
            )
        ],
        secrets=[
            SecretFinding(
                tool="detect-secrets",
                file="config/settings.py",
                line=8,
                severity="critical",
                title="AWS Access Key",
                description="AWS access key detected",
                recommendation="Remove key and use IAM roles",
                secret_type="AWS Access Key",
                entropy=4.8,
                is_verified=True
            )
        ],
        scan_duration=125.5,
        status="completed"
    )


@pytest.fixture
def report_service():
    """Create ReportService instance"""
    return ReportService()


class TestReportService:
    """Test cases for ReportService"""
    
    def test_generate_json_report_structure(self, report_service, sample_scan_results):
        """Test that JSON report has correct structure"""
        report = report_service.generate_json_report(sample_scan_results)
        
        # Check top-level structure
        assert "report_metadata" in report
        assert "executive_summary" in report
        assert "detailed_findings" in report
        assert "recommendations" in report
        
        # Check metadata structure
        metadata = report["report_metadata"]
        assert "generated_at" in metadata
        assert "report_version" in metadata
        assert metadata["scan_id"] == "test-scan-123"
        assert metadata["repository_url"] == "https://github.com/test/repo"
        assert metadata["scan_status"] == "completed"
        assert metadata["scan_duration_seconds"] == 125.5
        
        # Check executive summary
        summary = report["executive_summary"]
        assert summary["total_vulnerabilities"] == 11  # 2+3+5+1
        assert summary["severity_breakdown"]["critical"] == 2
        assert summary["severity_breakdown"]["high"] == 3
        assert summary["severity_breakdown"]["medium"] == 5
        assert summary["severity_breakdown"]["low"] == 1
        
        # Check finding types
        finding_types = summary["finding_types"]
        assert finding_types["static_analysis"] == 2
        assert finding_types["dependency_vulnerabilities"] == 1
        assert finding_types["secrets_found"] == 1
    
    def test_format_vulnerability_for_json(self, report_service):
        """Test vulnerability formatting for JSON"""
        vuln = Vulnerability(
            tool="bandit",
            file="test.py",
            line=10,
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            recommendation="Test recommendation",
            cve_id="CVE-2023-1234",
            confidence="medium"
        )
        
        formatted = report_service._format_vulnerability_for_json(vuln)
        
        assert formatted["tool"] == "bandit"
        assert formatted["file_path"] == "test.py"
        assert formatted["line_number"] == 10
        assert formatted["severity"] == "high"
        assert formatted["title"] == "Test Vulnerability"
        assert formatted["description"] == "Test description"
        assert formatted["recommendation"] == "Test recommendation"
        assert formatted["cve_id"] == "CVE-2023-1234"
        assert formatted["confidence"] == "medium"
        assert "id" in formatted
    
    def test_format_dependency_vulnerability_for_json(self, report_service):
        """Test dependency vulnerability formatting"""
        dep_vuln = DependencyVulnerability(
            tool="trivy",
            file="package.json",
            severity="critical",
            title="Vulnerable Package",
            description="Package has vulnerability",
            recommendation="Update package",
            package_name="lodash",
            installed_version="4.17.15",
            fixed_version="4.17.21",
            cve_id="CVE-2021-23337",
            cve_score=7.2
        )
        
        formatted = report_service._format_dependency_vulnerability_for_json(dep_vuln)
        
        # Check base vulnerability fields
        assert formatted["tool"] == "trivy"
        assert formatted["severity"] == "critical"
        
        # Check dependency-specific fields
        assert formatted["package_name"] == "lodash"
        assert formatted["installed_version"] == "4.17.15"
        assert formatted["fixed_version"] == "4.17.21"
        assert formatted["cve_score"] == 7.2
        assert formatted["vulnerability_type"] == "dependency"
    
    def test_format_secret_finding_for_json(self, report_service):
        """Test secret finding formatting"""
        secret = SecretFinding(
            tool="detect-secrets",
            file="config.py",
            line=5,
            severity="high",
            title="API Key",
            description="API key detected",
            recommendation="Use environment variable",
            secret_type="Generic API Key",
            entropy=4.5,
            is_verified=False
        )
        
        formatted = report_service._format_secret_finding_for_json(secret)
        
        # Check base vulnerability fields
        assert formatted["tool"] == "detect-secrets"
        assert formatted["severity"] == "high"
        
        # Check secret-specific fields
        assert formatted["secret_type"] == "Generic API Key"
        assert formatted["entropy_score"] == 4.5
        assert formatted["is_verified"] is False
        assert formatted["vulnerability_type"] == "secret"
    
    def test_generate_recommendations_with_critical_findings(self, report_service, sample_scan_results):
        """Test recommendation generation with critical findings"""
        recommendations = report_service._generate_recommendations(sample_scan_results)
        
        assert "priority_actions" in recommendations
        assert "security_best_practices" in recommendations
        assert "next_steps" in recommendations
        
        # Should have priority actions for critical and high severity
        priority_actions = recommendations["priority_actions"]
        assert any("critical" in action.lower() for action in priority_actions)
        assert any("high-severity" in action.lower() for action in priority_actions)
        assert any("secrets" in action.lower() for action in priority_actions)
        
        # Should have best practices
        best_practices = recommendations["security_best_practices"]
        assert any("dependencies" in practice.lower() for practice in best_practices)
        assert any("static analysis" in practice.lower() for practice in best_practices)
        
        # Should have next steps
        assert len(recommendations["next_steps"]) > 0
    
    def test_generate_recommendations_no_findings(self, report_service):
        """Test recommendation generation with no findings"""
        clean_results = ScanResults(
            scan_id="clean-scan",
            repository_url="https://github.com/test/clean",
            scan_date=datetime.now(),
            summary=ScanSummary(),
            static_analysis=[],
            dependencies=[],
            secrets=[],
            scan_duration=30.0,
            status="completed"
        )
        
        recommendations = report_service._generate_recommendations(clean_results)
        
        # Should still have general next steps even with no findings
        assert len(recommendations["next_steps"]) > 0
        # Priority actions should be minimal
        assert len(recommendations["priority_actions"]) == 0
    
    def test_get_json_report_bytes(self, report_service, sample_scan_results):
        """Test getting JSON report as bytes"""
        report_bytes = report_service.get_json_report_bytes(sample_scan_results)
        
        assert isinstance(report_bytes, bytes)
        
        # Should be valid JSON when decoded
        report_str = report_bytes.decode('utf-8')
        report_data = json.loads(report_str)
        
        assert "report_metadata" in report_data
        assert "executive_summary" in report_data
    
    def test_save_json_report_default_path(self, report_service, sample_scan_results, tmp_path):
        """Test saving JSON report with default path"""
        with patch('pathlib.Path.cwd', return_value=tmp_path):
            saved_path = report_service.save_json_report(sample_scan_results)
            
            assert saved_path.name == "scan_report_test-scan-123.json"
            assert saved_path.exists()
            
            # Verify content
            with open(saved_path, 'r') as f:
                report_data = json.load(f)
            
            assert report_data["report_metadata"]["scan_id"] == "test-scan-123"
    
    def test_save_json_report_custom_path(self, report_service, sample_scan_results, tmp_path):
        """Test saving JSON report with custom path"""
        custom_path = tmp_path / "custom_report.json"
        saved_path = report_service.save_json_report(sample_scan_results, custom_path)
        
        assert saved_path == custom_path
        assert custom_path.exists()
        
        # Verify content
        with open(custom_path, 'r') as f:
            report_data = json.load(f)
        
        assert report_data["report_metadata"]["scan_id"] == "test-scan-123"
    
    def test_json_report_serializable(self, report_service, sample_scan_results):
        """Test that generated JSON report is fully serializable"""
        report = report_service.generate_json_report(sample_scan_results)
        
        # Should not raise any exceptions
        json_str = json.dumps(report)
        
        # Should be able to parse back
        parsed = json.loads(json_str)
        assert parsed == report
    
    @patch('backend.app.services.report.datetime')
    def test_report_metadata_timestamp(self, mock_datetime, report_service, sample_scan_results):
        """Test that report metadata includes correct timestamp"""
        from datetime import timezone
        mock_now = datetime(2024, 1, 20, 15, 30, 45, tzinfo=timezone.utc)
        mock_datetime.now.return_value = mock_now
        
        report = report_service.generate_json_report(sample_scan_results)
        
        assert report["report_metadata"]["generated_at"] == "2024-01-20T15:30:45Z"
    
    def test_detailed_findings_structure(self, report_service, sample_scan_results):
        """Test detailed findings section structure"""
        report = report_service.generate_json_report(sample_scan_results)
        
        findings = report["detailed_findings"]
        
        # Check structure
        assert "static_analysis_vulnerabilities" in findings
        assert "dependency_vulnerabilities" in findings
        assert "secret_findings" in findings
        
        # Check counts match
        assert len(findings["static_analysis_vulnerabilities"]) == 2
        assert len(findings["dependency_vulnerabilities"]) == 1
        assert len(findings["secret_findings"]) == 1
        
        # Check that each finding has required fields
        static_vuln = findings["static_analysis_vulnerabilities"][0]
        assert "id" in static_vuln
        assert "tool" in static_vuln
        assert "file_path" in static_vuln
        assert "severity" in static_vuln
        
        dep_vuln = findings["dependency_vulnerabilities"][0]
        assert "package_name" in dep_vuln
        assert "vulnerability_type" in dep_vuln
        
        secret_finding = findings["secret_findings"][0]
        assert "secret_type" in secret_finding
        assert "vulnerability_type" in secret_finding


class TestPDFReportGeneration:
    """Test cases for PDF report generation"""
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_generate_pdf_report_success(self, report_service, sample_scan_results):
        """Test successful PDF report generation"""
        pdf_bytes = report_service.generate_pdf_report(sample_scan_results)
        
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        # PDF files start with %PDF
        assert pdf_bytes.startswith(b'%PDF')
    
    def test_generate_pdf_report_weasyprint_unavailable(self, report_service, sample_scan_results):
        """Test PDF generation when WeasyPrint is unavailable"""
        with patch('backend.app.services.report.WEASYPRINT_AVAILABLE', False):
            with pytest.raises(RuntimeError, match="WeasyPrint is not available"):
                report_service.generate_pdf_report(sample_scan_results)
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_generate_html_report_structure(self, report_service, sample_scan_results):
        """Test HTML report generation for PDF"""
        html_content = report_service._generate_html_report(sample_scan_results)
        
        assert isinstance(html_content, str)
        assert "<!DOCTYPE html>" in html_content
        assert "CodeShield Security Report" in html_content
        assert str(sample_scan_results.repository_url) in html_content
        assert sample_scan_results.scan_id in html_content
        
        # Check that findings are included
        assert "Static Analysis Vulnerabilities" in html_content
        assert "Dependency Vulnerabilities" in html_content
        assert "Secret Findings" in html_content
        
        # Check severity counts
        assert str(sample_scan_results.summary.critical) in html_content
        assert str(sample_scan_results.summary.high) in html_content
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_get_pdf_css_styles(self, report_service):
        """Test PDF CSS styles generation"""
        css_styles = report_service._get_pdf_css_styles()
        
        assert isinstance(css_styles, str)
        assert "@page" in css_styles
        assert "font-family" in css_styles
        assert ".severity-badge" in css_styles
        assert ".summary-card" in css_styles
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_save_pdf_report_default_path(self, report_service, sample_scan_results, tmp_path):
        """Test saving PDF report with default path"""
        with patch('pathlib.Path.cwd', return_value=tmp_path):
            saved_path = report_service.save_pdf_report(sample_scan_results)
            
            assert saved_path.name == "scan_report_test-scan-123.pdf"
            assert saved_path.exists()
            assert saved_path.stat().st_size > 0
            
            # Verify it's a PDF file
            with open(saved_path, 'rb') as f:
                content = f.read(4)
                assert content == b'%PDF'
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_save_pdf_report_custom_path(self, report_service, sample_scan_results, tmp_path):
        """Test saving PDF report with custom path"""
        custom_path = tmp_path / "custom_report.pdf"
        saved_path = report_service.save_pdf_report(sample_scan_results, custom_path)
        
        assert saved_path == custom_path
        assert custom_path.exists()
        assert custom_path.stat().st_size > 0
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_generate_pdf_report_with_empty_results(self, report_service):
        """Test PDF generation with empty scan results"""
        empty_results = ScanResults(
            scan_id="empty-scan",
            repository_url="https://github.com/test/empty",
            scan_date=datetime.now(),
            summary=ScanSummary(),
            static_analysis=[],
            dependencies=[],
            secrets=[],
            scan_duration=15.0,
            status="completed"
        )
        
        pdf_bytes = report_service.generate_pdf_report(empty_results)
        
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b'%PDF')
    
    def test_generate_report_with_fallback_pdf_success(self, report_service, sample_scan_results):
        """Test report generation with fallback - PDF success"""
        result = report_service.generate_report_with_fallback(sample_scan_results, "pdf")
        assert isinstance(result, bytes)
        
        # Check if we got a PDF (either WeasyPrint or ReportLab)
        if result.startswith(b'%PDF'):
            # Successfully generated PDF
            assert len(result) > 0
        else:
            # Should be JSON fallback
            json_content = json.loads(result.decode('utf-8'))
            assert "report_metadata" in json_content
    
    def test_generate_report_with_fallback_json_requested(self, report_service, sample_scan_results):
        """Test report generation with fallback - JSON requested"""
        result = report_service.generate_report_with_fallback(sample_scan_results, "json")
        
        assert isinstance(result, bytes)
        # Should be JSON content
        json_content = json.loads(result.decode('utf-8'))
        assert "report_metadata" in json_content
    
    def test_generate_pdf_report_html_error(self, report_service, sample_scan_results):
        """Test PDF generation when HTML processing fails"""
        if not WEASYPRINT_AVAILABLE:
            pytest.skip("WeasyPrint not available")
            
        with patch('weasyprint.HTML', side_effect=Exception("HTML processing failed")):
            with pytest.raises(RuntimeError, match="Failed to generate PDF report"):
                report_service.generate_pdf_report(sample_scan_results)
    
    def test_generate_report_with_fallback_pdf_error(self, report_service, sample_scan_results):
        """Test report generation with fallback when PDF fails"""
        with patch.object(report_service, 'generate_pdf_report', side_effect=Exception("PDF failed")):
            result = report_service.generate_report_with_fallback(sample_scan_results, "pdf")
            
            # Should fallback to JSON
            assert isinstance(result, bytes)
            json_content = json.loads(result.decode('utf-8'))
            assert "report_metadata" in json_content
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_html_template_with_no_findings(self, report_service):
        """Test HTML template rendering with no findings"""
        no_findings_results = ScanResults(
            scan_id="no-findings",
            repository_url="https://github.com/test/clean",
            scan_date=datetime.now(),
            summary=ScanSummary(),
            static_analysis=[],
            dependencies=[],
            secrets=[],
            scan_duration=20.0,
            status="completed"
        )
        
        html_content = report_service._generate_html_report(no_findings_results)
        
        # Should still have basic structure
        assert "CodeShield Security Report" in html_content
        assert "Executive Summary" in html_content
        assert "0" in html_content  # Zero findings
        
        # Should not have findings sections when empty
        assert "Static Analysis Vulnerabilities (0)" not in html_content
        assert "Dependency Vulnerabilities (0)" not in html_content
        assert "Secret Findings (0)" not in html_content
    
    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available")
    def test_html_template_special_characters(self, report_service):
        """Test HTML template with special characters in data"""
        special_results = ScanResults(
            scan_id="special-chars",
            repository_url="https://github.com/test/special",
            scan_date=datetime.now(),
            summary=ScanSummary(high=1),
            static_analysis=[
                Vulnerability(
                    tool="bandit",
                    file="src/test<script>.py",
                    line=1,
                    severity="high",
                    title="XSS & SQL Injection",
                    description="Contains <script> tags & special chars",
                    recommendation="Escape & validate input"
                )
            ],
            dependencies=[],
            secrets=[],
            scan_duration=30.0,
            status="completed"
        )
        
        html_content = report_service._generate_html_report(special_results)
        
        # Should contain the data (Jinja2 auto-escapes by default)
        assert "test&lt;script&gt;.py" in html_content or "test<script>.py" in html_content
        assert "XSS &amp; SQL Injection" in html_content or "XSS & SQL Injection" in html_content
    
    def test_generate_pdf_with_reportlab(self, report_service, sample_scan_results):
        """Test PDF generation using ReportLab"""
        if not REPORTLAB_AVAILABLE:
            pytest.skip("ReportLab not available")
        
        # Force use of ReportLab by calling the method directly
        pdf_bytes = report_service._generate_reportlab_pdf(sample_scan_results)
        
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b'%PDF')
    
    def test_pdf_generation_priority(self, report_service, sample_scan_results):
        """Test that PDF generation tries WeasyPrint first, then ReportLab"""
        pdf_bytes = report_service.generate_pdf_report(sample_scan_results)
        
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b'%PDF')