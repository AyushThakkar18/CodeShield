#!/usr/bin/env python3
"""
Demo script for ReportService functionality
"""

import json
from datetime import datetime
from pathlib import Path

from app.services.report import ReportService
from app.models.scan import (
    ScanResults, ScanSummary, Vulnerability, DependencyVulnerability, SecretFinding
)


def create_sample_scan_results():
    """Create sample scan results for demonstration"""
    return ScanResults(
        scan_id="demo-scan-001",
        repository_url="https://github.com/example/vulnerable-app",
        scan_date=datetime.now(),
        summary=ScanSummary(
            critical=1,
            high=2,
            medium=3,
            low=1
        ),
        static_analysis=[
            Vulnerability(
                tool="bandit",
                file="src/app.py",
                line=42,
                severity="high",
                title="SQL Injection Risk",
                description="Potential SQL injection vulnerability detected in database query",
                recommendation="Use parameterized queries or ORM to prevent SQL injection",
                confidence="high"
            ),
            Vulnerability(
                tool="bandit",
                file="src/auth.py",
                line=15,
                severity="medium",
                title="Hardcoded Password",
                description="Password appears to be hardcoded in source code",
                recommendation="Use environment variables or secure configuration for passwords"
            )
        ],
        dependencies=[
            DependencyVulnerability(
                tool="trivy",
                file="requirements.txt",
                severity="critical",
                title="Known CVE in requests library",
                description="The requests library version has a known security vulnerability",
                recommendation="Update requests to version 2.28.0 or higher",
                package_name="requests",
                installed_version="2.25.1",
                fixed_version="2.28.0",
                cve_id="CVE-2023-32681",
                cve_score=9.1
            ),
            DependencyVulnerability(
                tool="trivy",
                file="package.json",
                severity="high",
                title="Vulnerable lodash version",
                description="lodash library has prototype pollution vulnerability",
                recommendation="Update lodash to version 4.17.21 or higher",
                package_name="lodash",
                installed_version="4.17.15",
                fixed_version="4.17.21",
                cve_id="CVE-2021-23337",
                cve_score=7.2
            )
        ],
        secrets=[
            SecretFinding(
                tool="detect-secrets",
                file="config/settings.py",
                line=8,
                severity="critical",
                title="AWS Access Key",
                description="AWS access key detected in configuration file",
                recommendation="Remove key from source code and use IAM roles or environment variables",
                secret_type="AWS Access Key",
                entropy=4.8,
                is_verified=True
            )
        ],
        scan_duration=145.2,
        status="completed"
    )


def main():
    """Demonstrate ReportService functionality"""
    print("🔍 CodeShield Report Service Demo")
    print("=" * 50)
    
    # Create sample data
    scan_results = create_sample_scan_results()
    report_service = ReportService()
    
    print(f"📊 Sample scan results created:")
    print(f"   - Repository: {scan_results.repository_url}")
    print(f"   - Total vulnerabilities: {scan_results.summary.total}")
    print(f"   - Critical: {scan_results.summary.critical}")
    print(f"   - High: {scan_results.summary.high}")
    print(f"   - Medium: {scan_results.summary.medium}")
    print(f"   - Low: {scan_results.summary.low}")
    print()
    
    # Generate JSON report
    print("📄 Generating JSON report...")
    json_report = report_service.generate_json_report(scan_results)
    
    # Save JSON report
    json_path = Path("demo_report.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_report, f, indent=2, ensure_ascii=False)
    
    print(f"   ✅ JSON report saved to: {json_path}")
    print(f"   📏 Report size: {json_path.stat().st_size} bytes")
    print()
    
    # Show report structure
    print("📋 JSON Report Structure:")
    for key in json_report.keys():
        if key == "detailed_findings":
            findings = json_report[key]
            print(f"   - {key}:")
            for finding_type, finding_list in findings.items():
                print(f"     - {finding_type}: {len(finding_list)} items")
        elif key == "executive_summary":
            summary = json_report[key]
            print(f"   - {key}: {summary['total_vulnerabilities']} total vulnerabilities")
        else:
            print(f"   - {key}")
    print()
    
    # Try PDF generation
    print("📑 Attempting PDF report generation...")
    try:
        pdf_bytes = report_service.generate_pdf_report(scan_results)
        pdf_path = Path("demo_report.pdf")
        with open(pdf_path, 'wb') as f:
            f.write(pdf_bytes)
        print(f"   ✅ PDF report saved to: {pdf_path}")
        print(f"   📏 PDF size: {len(pdf_bytes)} bytes")
    except RuntimeError as e:
        print(f"   ⚠️  PDF generation failed: {e}")
        print("   💡 Using fallback to JSON...")
        
        # Demonstrate fallback functionality
        fallback_bytes = report_service.generate_report_with_fallback(scan_results, "pdf")
        fallback_path = Path("demo_report_fallback.json")
        with open(fallback_path, 'wb') as f:
            f.write(fallback_bytes)
        print(f"   ✅ Fallback JSON report saved to: {fallback_path}")
    print()
    
    # Show recommendations
    print("💡 Sample Recommendations:")
    recommendations = json_report["recommendations"]
    if recommendations["priority_actions"]:
        print("   Priority Actions:")
        for i, action in enumerate(recommendations["priority_actions"][:3], 1):
            print(f"   {i}. {action}")
    print()
    
    print("✨ Demo completed successfully!")
    print("\nGenerated files:")
    for file_path in [Path("demo_report.json"), Path("demo_report.pdf"), Path("demo_report_fallback.json")]:
        if file_path.exists():
            print(f"   - {file_path} ({file_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()