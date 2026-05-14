"""
Report generation service for CodeShield security scanning
"""

import json
import logging
import warnings
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pathlib import Path
from io import BytesIO

# Suppress WeasyPrint warnings during import
import sys
import os
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

# Suppress WeasyPrint output during import by redirecting both stdout and stderr
try:
    # Save original stderr and stdout
    original_stderr = sys.stderr
    original_stdout = sys.stdout
    
    # Redirect to null during import
    with open(os.devnull, 'w') as devnull:
        sys.stderr = devnull
        sys.stdout = devnull
        try:
            from weasyprint import HTML, CSS
            from jinja2 import Template
            WEASYPRINT_AVAILABLE = True
        finally:
            # Restore original streams
            sys.stderr = original_stderr
            sys.stdout = original_stdout
except (ImportError, OSError):
    # Restore streams in case of exception
    sys.stderr = original_stderr
    sys.stdout = original_stdout
    WEASYPRINT_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from ..models.scan import ScanResults, Vulnerability, DependencyVulnerability, SecretFinding


class ReportService:
    """Service for generating security scan reports in various formats"""
    
    def __init__(self):
        """Initialize the report service"""
        pass
    
    def generate_json_report(self, results: ScanResults) -> Dict[str, Any]:
        """
        Generate a structured JSON report from scan results
        
        Args:
            results: Complete scan results to format
            
        Returns:
            Dictionary containing formatted report data
        """
        # Convert Pydantic model to dict and format for JSON output
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "report_version": "1.0",
                "scan_id": results.scan_id,
                "repository_url": str(results.repository_url),
                "scan_date": results.scan_date.isoformat() + "Z",
                "scan_duration_seconds": results.scan_duration,
                "scan_status": results.status
            },
            "executive_summary": {
                "total_vulnerabilities": results.summary.total,
                "severity_breakdown": {
                    "critical": results.summary.critical,
                    "high": results.summary.high,
                    "medium": results.summary.medium,
                    "low": results.summary.low
                },
                "finding_types": {
                    "static_analysis": len(results.static_analysis),
                    "dependency_vulnerabilities": len(results.dependencies),
                    "secrets_found": len(results.secrets)
                }
            },
            "detailed_findings": {
                "static_analysis_vulnerabilities": [
                    self._format_vulnerability_for_json(vuln) 
                    for vuln in results.static_analysis
                ],
                "dependency_vulnerabilities": [
                    self._format_dependency_vulnerability_for_json(vuln) 
                    for vuln in results.dependencies
                ],
                "secret_findings": [
                    self._format_secret_finding_for_json(secret) 
                    for secret in results.secrets
                ]
            },
            "recommendations": self._generate_recommendations(results)
        }
        
        return report_data
    
    def _format_vulnerability_for_json(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Format a vulnerability for JSON output"""
        return {
            "id": f"{vuln.tool}_{hash(f'{vuln.file}_{vuln.line}_{vuln.title}')}",
            "tool": vuln.tool,
            "file_path": vuln.file,
            "line_number": vuln.line,
            "severity": vuln.severity,
            "title": vuln.title,
            "description": vuln.description,
            "recommendation": vuln.recommendation,
            "cve_id": vuln.cve_id,
            "confidence": vuln.confidence
        }
    
    def _format_dependency_vulnerability_for_json(self, vuln: DependencyVulnerability) -> Dict[str, Any]:
        """Format a dependency vulnerability for JSON output"""
        base_data = self._format_vulnerability_for_json(vuln)
        base_data.update({
            "package_name": vuln.package_name,
            "installed_version": vuln.installed_version,
            "fixed_version": vuln.fixed_version,
            "cve_score": vuln.cve_score,
            "vulnerability_type": "dependency"
        })
        return base_data
    
    def _format_secret_finding_for_json(self, secret: SecretFinding) -> Dict[str, Any]:
        """Format a secret finding for JSON output"""
        base_data = self._format_vulnerability_for_json(secret)
        base_data.update({
            "secret_type": secret.secret_type,
            "entropy_score": secret.entropy,
            "is_verified": secret.is_verified,
            "vulnerability_type": "secret"
        })
        return base_data
    
    def _generate_recommendations(self, results: ScanResults) -> Dict[str, Any]:
        """Generate high-level recommendations based on scan results"""
        recommendations = {
            "priority_actions": [],
            "security_best_practices": [],
            "next_steps": []
        }
        
        # Priority actions based on critical/high severity findings
        if results.summary.critical > 0:
            recommendations["priority_actions"].append(
                f"Address {results.summary.critical} critical vulnerabilities immediately"
            )
        
        if results.summary.high > 0:
            recommendations["priority_actions"].append(
                f"Review and fix {results.summary.high} high-severity vulnerabilities"
            )
        
        # Specific recommendations based on finding types
        if results.secrets:
            recommendations["priority_actions"].append(
                "Remove or rotate exposed secrets and credentials"
            )
        
        if results.dependencies:
            recommendations["security_best_practices"].append(
                "Regularly update dependencies to latest secure versions"
            )
            recommendations["security_best_practices"].append(
                "Implement automated dependency vulnerability scanning in CI/CD"
            )
        
        if results.static_analysis:
            recommendations["security_best_practices"].append(
                "Integrate static analysis tools into development workflow"
            )
        
        # General next steps
        recommendations["next_steps"].extend([
            "Review all findings and create remediation plan",
            "Implement security scanning in CI/CD pipeline",
            "Establish regular security review process",
            "Consider security training for development team"
        ])
        
        return recommendations
    
    def save_json_report(self, results: ScanResults, output_path: Optional[Path] = None) -> Path:
        """
        Save JSON report to file
        
        Args:
            results: Scan results to save
            output_path: Optional path to save file, defaults to scan_id.json
            
        Returns:
            Path where the report was saved
        """
        if output_path is None:
            output_path = Path(f"scan_report_{results.scan_id}.json")
        
        report_data = self.generate_json_report(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def get_json_report_bytes(self, results: ScanResults) -> bytes:
        """
        Get JSON report as bytes for download
        
        Args:
            results: Scan results to format
            
        Returns:
            JSON report as UTF-8 encoded bytes
        """
        report_data = self.generate_json_report(results)
        return json.dumps(report_data, indent=2, ensure_ascii=False).encode('utf-8')
    
    def generate_pdf_report(self, results: ScanResults) -> bytes:
        """
        Generate a PDF report from scan results
        
        Args:
            results: Complete scan results to format
            
        Returns:
            PDF report as bytes
            
        Raises:
            RuntimeError: If PDF generation fails
        """
        # Try WeasyPrint first, then fall back to ReportLab
        if WEASYPRINT_AVAILABLE:
            try:
                return self._generate_weasyprint_pdf(results)
            except Exception as e:
                logging.warning(f"WeasyPrint PDF generation failed, trying ReportLab: {e}")
        
        if REPORTLAB_AVAILABLE:
            try:
                return self._generate_reportlab_pdf(results)
            except Exception as e:
                logging.error(f"ReportLab PDF generation failed: {str(e)}")
                raise RuntimeError(f"Failed to generate PDF report with ReportLab: {str(e)}")
        
        raise RuntimeError("No PDF generation libraries available (WeasyPrint or ReportLab)")
    
    def _generate_weasyprint_pdf(self, results: ScanResults) -> bytes:
        """Generate PDF using WeasyPrint"""
        # Generate HTML content for the PDF
        html_content = self._generate_html_report(results)
        
        # Generate PDF from HTML
        html_doc = HTML(string=html_content)
        css_styles = self._get_pdf_css_styles()
        
        pdf_buffer = BytesIO()
        html_doc.write_pdf(pdf_buffer, stylesheets=[CSS(string=css_styles)])
        
        return pdf_buffer.getvalue()
    
    def _generate_reportlab_pdf(self, results: ScanResults) -> bytes:
        """Generate PDF using ReportLab"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*inch)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#34495e')
        )
        
        # Build content
        content = []
        
        # Title
        content.append(Paragraph("CodeShield Security Report", title_style))
        content.append(Spacer(1, 20))
        
        # Report metadata
        metadata_data = [
            ['Repository:', str(results.repository_url)],
            ['Scan Date:', results.scan_date.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Scan Duration:', f"{results.scan_duration:.1f} seconds"],
            ['Report Generated:', datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Scan ID:', results.scan_id]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))
        content.append(metadata_table)
        content.append(Spacer(1, 30))
        
        # Executive Summary
        content.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ['Severity', 'Count'],
            ['Critical', str(results.summary.critical)],
            ['High', str(results.summary.high)],
            ['Medium', str(results.summary.medium)],
            ['Low', str(results.summary.low)],
            ['Total', str(results.summary.total)]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#e74c3c')),  # Critical
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#f39c12')),  # High
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#f1c40f')),  # Medium
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#27ae60')),  # Low
            ('TEXTCOLOR', (0, 1), (-1, 4), colors.white),
        ]))
        content.append(summary_table)
        content.append(Spacer(1, 20))
        
        # Static Analysis Vulnerabilities
        if results.static_analysis:
            content.append(Paragraph(f"Static Analysis Vulnerabilities ({len(results.static_analysis)})", heading_style))
            
            static_data = [['File', 'Line', 'Severity', 'Title', 'Tool']]
            for vuln in results.static_analysis:
                static_data.append([
                    vuln.file,
                    str(vuln.line) if vuln.line else 'N/A',
                    vuln.severity.upper(),
                    vuln.title[:50] + '...' if len(vuln.title) > 50 else vuln.title,
                    vuln.tool
                ])
            
            static_table = Table(static_data, colWidths=[1.5*inch, 0.5*inch, 0.8*inch, 2.5*inch, 0.7*inch])
            static_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ]))
            content.append(static_table)
            content.append(Spacer(1, 20))
        
        # Dependency Vulnerabilities
        if results.dependencies:
            content.append(Paragraph(f"Dependency Vulnerabilities ({len(results.dependencies)})", heading_style))
            
            dep_data = [['Package', 'Current', 'Fixed', 'Severity', 'CVE']]
            for dep in results.dependencies:
                dep_data.append([
                    dep.package_name,
                    dep.installed_version,
                    dep.fixed_version or 'N/A',
                    dep.severity.upper(),
                    dep.cve_id or 'N/A'
                ])
            
            dep_table = Table(dep_data, colWidths=[1.5*inch, 1*inch, 1*inch, 0.8*inch, 1.2*inch])
            dep_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ]))
            content.append(dep_table)
            content.append(Spacer(1, 20))
        
        # Secret Findings
        if results.secrets:
            content.append(Paragraph(f"Secret Findings ({len(results.secrets)})", heading_style))
            
            secret_data = [['File', 'Line', 'Secret Type', 'Severity', 'Verified']]
            for secret in results.secrets:
                secret_data.append([
                    secret.file,
                    str(secret.line) if secret.line else 'N/A',
                    secret.secret_type,
                    secret.severity.upper(),
                    'Yes' if secret.is_verified else 'No' if secret.is_verified is not None else 'Unknown'
                ])
            
            secret_table = Table(secret_data, colWidths=[1.5*inch, 0.5*inch, 1.5*inch, 0.8*inch, 0.7*inch])
            secret_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ]))
            content.append(secret_table)
            content.append(Spacer(1, 20))
        
        # Recommendations
        json_report = self.generate_json_report(results)
        recommendations = json_report["recommendations"]
        
        content.append(Paragraph("Recommendations", heading_style))
        
        if recommendations["priority_actions"]:
            content.append(Paragraph("Priority Actions:", styles['Heading3']))
            for i, action in enumerate(recommendations["priority_actions"], 1):
                content.append(Paragraph(f"{i}. {action}", styles['Normal']))
            content.append(Spacer(1, 10))
        
        if recommendations["security_best_practices"]:
            content.append(Paragraph("Security Best Practices:", styles['Heading3']))
            for practice in recommendations["security_best_practices"]:
                content.append(Paragraph(f"• {practice}", styles['Normal']))
            content.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(content)
        return buffer.getvalue()
    
    def _generate_html_report(self, results: ScanResults) -> str:
        """Generate HTML content for PDF report"""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CodeShield Security Report</title>
</head>
<body>
    <div class="header">
        <h1>CodeShield Security Report</h1>
        <div class="report-info">
            <p><strong>Repository:</strong> {{ repository_url }}</p>
            <p><strong>Scan Date:</strong> {{ scan_date }}</p>
            <p><strong>Scan Duration:</strong> {{ scan_duration }}s</p>
            <p><strong>Report Generated:</strong> {{ generated_at }}</p>
        </div>
    </div>
    
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>{{ summary.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{{ summary.high }}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{{ summary.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{{ summary.low }}</h3>
                <p>Low</p>
            </div>
        </div>
        <p class="total-findings">Total Vulnerabilities Found: <strong>{{ summary.total }}</strong></p>
    </div>
    
    {% if static_analysis %}
    <div class="findings-section">
        <h2>Static Analysis Vulnerabilities ({{ static_analysis|length }})</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>File</th>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Tool</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in static_analysis %}
                <tr class="severity-{{ vuln.severity }}">
                    <td>{{ vuln.file }}</td>
                    <td>{{ vuln.line or 'N/A' }}</td>
                    <td><span class="severity-badge {{ vuln.severity }}">{{ vuln.severity.upper() }}</span></td>
                    <td>{{ vuln.title }}</td>
                    <td>{{ vuln.tool }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if dependencies %}
    <div class="findings-section">
        <h2>Dependency Vulnerabilities ({{ dependencies|length }})</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Current Version</th>
                    <th>Fixed Version</th>
                    <th>Severity</th>
                    <th>CVE</th>
                </tr>
            </thead>
            <tbody>
                {% for dep in dependencies %}
                <tr class="severity-{{ dep.severity }}">
                    <td>{{ dep.package_name }}</td>
                    <td>{{ dep.installed_version }}</td>
                    <td>{{ dep.fixed_version or 'N/A' }}</td>
                    <td><span class="severity-badge {{ dep.severity }}">{{ dep.severity.upper() }}</span></td>
                    <td>{{ dep.cve_id or 'N/A' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if secrets %}
    <div class="findings-section">
        <h2>Secret Findings ({{ secrets|length }})</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>File</th>
                    <th>Line</th>
                    <th>Secret Type</th>
                    <th>Severity</th>
                    <th>Verified</th>
                </tr>
            </thead>
            <tbody>
                {% for secret in secrets %}
                <tr class="severity-{{ secret.severity }}">
                    <td>{{ secret.file }}</td>
                    <td>{{ secret.line or 'N/A' }}</td>
                    <td>{{ secret.secret_type }}</td>
                    <td><span class="severity-badge {{ secret.severity }}">{{ secret.severity.upper() }}</span></td>
                    <td>{{ 'Yes' if secret.is_verified else 'No' if secret.is_verified is not none else 'Unknown' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        {% if recommendations.priority_actions %}
        <h3>Priority Actions</h3>
        <ul>
            {% for action in recommendations.priority_actions %}
            <li>{{ action }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        
        {% if recommendations.security_best_practices %}
        <h3>Security Best Practices</h3>
        <ul>
            {% for practice in recommendations.security_best_practices %}
            <li>{{ practice }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        
        {% if recommendations.next_steps %}
        <h3>Next Steps</h3>
        <ul>
            {% for step in recommendations.next_steps %}
            <li>{{ step }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>
    
    <div class="footer">
        <p>Generated by CodeShield Security Scanner</p>
        <p>Report ID: {{ scan_id }}</p>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        report_data = self.generate_json_report(results)
        
        return template.render(
            repository_url=str(results.repository_url),
            scan_date=results.scan_date.strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_duration=results.scan_duration,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_id=results.scan_id,
            summary=results.summary,
            static_analysis=results.static_analysis,
            dependencies=results.dependencies,
            secrets=results.secrets,
            recommendations=report_data["recommendations"]
        )
    
    def _get_pdf_css_styles(self) -> str:
        """Get CSS styles for PDF report"""
        return """
        @page {
            margin: 1in;
            @top-center {
                content: "CodeShield Security Report";
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #666;
            }
        }
        
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
        }
        
        .header {
            border-bottom: 2px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #2c3e50;
            margin: 0 0 15px 0;
            font-size: 28pt;
        }
        
        .report-info p {
            margin: 5px 0;
            font-size: 11pt;
        }
        
        .executive-summary {
            margin-bottom: 30px;
        }
        
        .executive-summary h2 {
            color: #2c3e50;
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 10px;
        }
        
        .summary-grid {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
        }
        
        .summary-card {
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            min-width: 80px;
            margin: 0 5px;
        }
        
        .summary-card.critical {
            background-color: #e74c3c;
            color: white;
        }
        
        .summary-card.high {
            background-color: #f39c12;
            color: white;
        }
        
        .summary-card.medium {
            background-color: #f1c40f;
            color: #333;
        }
        
        .summary-card.low {
            background-color: #27ae60;
            color: white;
        }
        
        .summary-card h3 {
            margin: 0;
            font-size: 24pt;
        }
        
        .summary-card p {
            margin: 5px 0 0 0;
            font-size: 10pt;
        }
        
        .total-findings {
            text-align: center;
            font-size: 14pt;
            margin-top: 20px;
        }
        
        .findings-section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }
        
        .findings-section h2 {
            color: #2c3e50;
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 10px;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 9pt;
        }
        
        .findings-table th {
            background-color: #34495e;
            color: white;
            padding: 10px 8px;
            text-align: left;
            font-weight: bold;
        }
        
        .findings-table td {
            padding: 8px;
            border-bottom: 1px solid #ecf0f1;
            vertical-align: top;
        }
        
        .findings-table tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        .severity-badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 8pt;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background-color: #e74c3c;
            color: white;
        }
        
        .severity-badge.high {
            background-color: #f39c12;
            color: white;
        }
        
        .severity-badge.medium {
            background-color: #f1c40f;
            color: #333;
        }
        
        .severity-badge.low {
            background-color: #27ae60;
            color: white;
        }
        
        .recommendations {
            margin-bottom: 30px;
        }
        
        .recommendations h2 {
            color: #2c3e50;
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 10px;
        }
        
        .recommendations h3 {
            color: #34495e;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        
        .recommendations ul {
            padding-left: 20px;
        }
        
        .recommendations li {
            margin-bottom: 8px;
            line-height: 1.4;
        }
        
        .footer {
            border-top: 1px solid #bdc3c7;
            padding-top: 20px;
            margin-top: 40px;
            text-align: center;
            color: #7f8c8d;
            font-size: 10pt;
        }
        
        .footer p {
            margin: 5px 0;
        }
        """
    
    def save_pdf_report(self, results: ScanResults, output_path: Optional[Path] = None) -> Path:
        """
        Save PDF report to file
        
        Args:
            results: Scan results to save
            output_path: Optional path to save file, defaults to scan_id.pdf
            
        Returns:
            Path where the report was saved
            
        Raises:
            RuntimeError: If PDF generation fails
        """
        if output_path is None:
            output_path = Path(f"scan_report_{results.scan_id}.pdf")
        
        pdf_bytes = self.generate_pdf_report(results)
        
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
        
        return output_path
    
    def generate_report_with_fallback(self, results: ScanResults, format_type: str = "pdf") -> bytes:
        """
        Generate report with fallback to JSON if PDF generation fails
        
        Args:
            results: Scan results to format
            format_type: Desired format ("pdf" or "json")
            
        Returns:
            Report as bytes (PDF if successful, JSON as fallback)
        """
        if format_type.lower() == "json":
            return self.get_json_report_bytes(results)
        
        try:
            return self.generate_pdf_report(results)
        except Exception as e:
            logging.warning(f"PDF generation failed, falling back to JSON: {str(e)}")
            return self.get_json_report_bytes(results)