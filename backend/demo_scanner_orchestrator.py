#!/usr/bin/env python3
"""
Demo script for the Scanner Orchestrator Service

This script demonstrates the scanner orchestration functionality by:
1. Creating a temporary repository with known vulnerabilities
2. Running the comprehensive scan orchestrator
3. Displaying the aggregated results

Usage:
    python demo_scanner_orchestrator.py
"""

import asyncio
import tempfile
import json
from pathlib import Path
from datetime import datetime

from app.services.scanner_orchestrator import ScannerService
from app.models.config import SecurityToolsConfig


async def create_demo_repository():
    """Create a temporary repository with known security issues"""
    temp_dir = tempfile.mkdtemp(prefix="codeshield_demo_")
    repo_path = Path(temp_dir)
    
    print(f"Creating demo repository at: {repo_path}")
    
    # Create Python file with Bandit vulnerabilities
    vulnerable_py = repo_path / "vulnerable_app.py"
    vulnerable_py.write_text("""
#!/usr/bin/env python3
import subprocess
import os
import tempfile

# B105: Hardcoded password vulnerability
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"

# B602: subprocess with shell=True vulnerability
def execute_command(user_input):
    # This is vulnerable to command injection
    result = subprocess.call(user_input, shell=True)
    return result

# B108: Insecure temp file creation
def create_temp_file():
    temp_file = "/tmp/myapp_" + str(os.getpid()) + ".tmp"
    with open(temp_file, "w") as f:
        f.write("sensitive data")
    return temp_file

# B104: Binding to all interfaces
def start_server():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 8080))  # Vulnerable: binds to all interfaces
    s.listen(5)
    return s

if __name__ == "__main__":
    print("Starting vulnerable application...")
    server = start_server()
    temp_file = create_temp_file()
    execute_command("echo 'Hello World'")
""")
    
    # Create requirements.txt with vulnerable dependencies
    requirements = repo_path / "requirements.txt"
    requirements.write_text("""
# Vulnerable dependencies for testing
requests==2.20.0
django==2.0.0
flask==0.12.0
pyyaml==3.12
jinja2==2.8
""")
    
    # Create configuration file with secrets
    config_py = repo_path / "config.py"
    config_py.write_text("""
# Configuration file with hardcoded secrets

# AWS credentials (should be in environment variables)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database configuration
DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "username": "admin",
    "password": "admin123",  # Hardcoded password
    "database": "myapp"
}

# API keys
GITHUB_TOKEN = "ghp_EXAMPLE_TOKEN_FOR_TESTING_ONLY"
SLACK_WEBHOOK = "https://hooks.slack.com/services/EXAMPLE/EXAMPLE/EXAMPLE_WEBHOOK_URL"
OPENAI_API_KEY = "sk-EXAMPLE_KEY_FOR_TESTING_ONLY"

# JWT secret
JWT_SECRET = "my-super-secret-jwt-key-that-should-not-be-hardcoded"
""")
    
    # Create a package.json for Node.js dependencies (Trivy can scan these too)
    package_json = repo_path / "package.json"
    package_json.write_text("""
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4",
    "express": "4.15.0",
    "moment": "2.19.0"
  }
}
""")
    
    # Create a Dockerfile with potential issues
    dockerfile = repo_path / "Dockerfile"
    dockerfile.write_text("""
FROM ubuntu:16.04

# Running as root (security issue)
USER root

# Installing packages without version pinning
RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    curl \\
    wget

# Hardcoded secrets in Dockerfile
ENV DATABASE_PASSWORD=secret123
ENV API_KEY=sk-1234567890abcdef

# Copying everything (including secrets)
COPY . /app
WORKDIR /app

# Installing Python dependencies
RUN pip3 install -r requirements.txt

# Exposing port
EXPOSE 8080

# Running as root
CMD ["python3", "vulnerable_app.py"]
""")
    
    return str(repo_path)


async def run_comprehensive_scan(repo_path: str):
    """Run the comprehensive security scan using the orchestrator"""
    print("\n" + "="*60)
    print("STARTING COMPREHENSIVE SECURITY SCAN")
    print("="*60)
    
    # Initialize the scanner service with default configuration
    config = SecurityToolsConfig()
    scanner_service = ScannerService(config)
    
    # Check scanner availability first
    print("\nChecking scanner availability...")
    scanner_status = await scanner_service.get_scanner_status()
    
    for scanner_name, available in scanner_status.items():
        status_icon = "✓" if available else "✗"
        print(f"  {status_icon} {scanner_name}: {'Available' if available else 'Not Available'}")
    
    # Run the comprehensive scan
    print(f"\nScanning repository: {repo_path}")
    print("This may take a few moments...")
    
    start_time = datetime.now()
    
    try:
        results = await scanner_service.scan_repository(
            repo_path=repo_path,
            repository_url="https://github.com/demo/vulnerable-repo",
            scan_id="demo-scan-001"
        )
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        print(f"\nScan completed in {scan_duration:.2f} seconds")
        print(f"Scan status: {results.status.upper()}")
        
        return results
        
    except Exception as e:
        print(f"\nScan failed with error: {str(e)}")
        return None


def display_scan_results(results):
    """Display the scan results in a formatted way"""
    if not results:
        print("No results to display.")
        return
    
    print("\n" + "="*60)
    print("SCAN RESULTS SUMMARY")
    print("="*60)
    
    # Display summary statistics
    summary = results.summary
    print(f"\nTotal Issues Found: {summary.total}")
    print(f"  🔴 Critical: {summary.critical}")
    print(f"  🟠 High:     {summary.high}")
    print(f"  🟡 Medium:   {summary.medium}")
    print(f"  🟢 Low:      {summary.low}")
    
    # Display static analysis results
    if results.static_analysis:
        print(f"\n📊 STATIC ANALYSIS FINDINGS ({len(results.static_analysis)} issues)")
        print("-" * 50)
        for i, vuln in enumerate(results.static_analysis[:5], 1):  # Show first 5
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln.severity, "⚪")
            print(f"{i}. {severity_icon} {vuln.title}")
            print(f"   File: {vuln.file}:{vuln.line or 'N/A'}")
            print(f"   Tool: {vuln.tool}")
            print(f"   Fix: {vuln.recommendation[:80]}...")
            print()
        
        if len(results.static_analysis) > 5:
            print(f"   ... and {len(results.static_analysis) - 5} more issues")
    
    # Display dependency vulnerabilities
    if results.dependencies:
        print(f"\n📦 DEPENDENCY VULNERABILITIES ({len(results.dependencies)} issues)")
        print("-" * 50)
        for i, vuln in enumerate(results.dependencies[:5], 1):  # Show first 5
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln.severity, "⚪")
            print(f"{i}. {severity_icon} {vuln.title}")
            print(f"   Package: {vuln.package_name} ({vuln.installed_version})")
            print(f"   CVE: {vuln.cve_id or 'N/A'}")
            if vuln.fixed_version:
                print(f"   Fix: Update to {vuln.fixed_version}")
            print()
        
        if len(results.dependencies) > 5:
            print(f"   ... and {len(results.dependencies) - 5} more issues")
    
    # Display secret findings
    if results.secrets:
        print(f"\n🔐 SECRET DETECTION FINDINGS ({len(results.secrets)} issues)")
        print("-" * 50)
        for i, secret in enumerate(results.secrets[:5], 1):  # Show first 5
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(secret.severity, "⚪")
            print(f"{i}. {severity_icon} {secret.title}")
            print(f"   File: {secret.file}:{secret.line or 'N/A'}")
            print(f"   Type: {secret.secret_type}")
            print(f"   Fix: {secret.recommendation[:80]}...")
            print()
        
        if len(results.secrets) > 5:
            print(f"   ... and {len(results.secrets) - 5} more issues")
    
    # Display scan metadata
    print(f"\n📋 SCAN METADATA")
    print("-" * 50)
    print(f"Scan ID: {results.scan_id}")
    print(f"Repository: {results.repository_url}")
    print(f"Scan Date: {results.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration: {results.scan_duration:.2f} seconds")
    print(f"Status: {results.status.upper()}")


async def main():
    """Main demo function"""
    print("CodeShield Scanner Orchestrator Demo")
    print("=" * 40)
    
    try:
        # Create demo repository
        repo_path = await create_demo_repository()
        
        # Run comprehensive scan
        results = await run_comprehensive_scan(repo_path)
        
        # Display results
        display_scan_results(results)
        
        # Optionally save results to JSON
        if results:
            output_file = "demo_scan_results.json"
            with open(output_file, 'w') as f:
                # Convert to dict for JSON serialization
                results_dict = {
                    "scan_id": results.scan_id,
                    "repository_url": str(results.repository_url),
                    "scan_date": results.scan_date.isoformat(),
                    "summary": {
                        "critical": results.summary.critical,
                        "high": results.summary.high,
                        "medium": results.summary.medium,
                        "low": results.summary.low,
                        "total": results.summary.total
                    },
                    "static_analysis_count": len(results.static_analysis),
                    "dependencies_count": len(results.dependencies),
                    "secrets_count": len(results.secrets),
                    "scan_duration": results.scan_duration,
                    "status": results.status
                }
                json.dump(results_dict, f, indent=2)
            
            print(f"\n💾 Detailed results saved to: {output_file}")
        
        print(f"\n🗑️  Demo repository created at: {repo_path}")
        print("You can manually delete this directory when done.")
        
    except Exception as e:
        print(f"\nDemo failed with error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())