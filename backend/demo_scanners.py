#!/usr/bin/env python3
"""
Demo script showing how to use the security scanners
"""

import asyncio
import tempfile
from pathlib import Path

from app.services.scanners import BanditScanner, TrivyScanner, SecretScanner
from app.models.config import BanditConfig, TrivyConfig, SecretScannerConfig


async def demo_scanners():
    """Demonstrate the security scanners with sample vulnerable code"""
    
    # Create a temporary directory with vulnerable code
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
# AWS access key (realistic format)
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token (realistic format)  
github_token = "ghp_1234567890abcdef1234567890abcdef12345678"

# Private key
private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btNiisUckms0
-----END RSA PRIVATE KEY-----'''

# Database connection string
db_url = "postgresql://user:password123@localhost:5432/mydb"
""")
        
        print(f"Created test repository at: {repo_path}")
        print("=" * 60)
        
        # Test Bandit Scanner
        print("🔍 Testing Bandit Scanner...")
        try:
            bandit_config = BanditConfig()
            bandit_scanner = BanditScanner(bandit_config)
            bandit_results = await bandit_scanner.scan(str(repo_path))
            
            print(f"✅ Bandit found {len(bandit_results)} vulnerabilities:")
            for vuln in bandit_results[:3]:  # Show first 3
                print(f"  - {vuln.severity.upper()}: {vuln.title} in {vuln.file}:{vuln.line}")
            if len(bandit_results) > 3:
                print(f"  ... and {len(bandit_results) - 3} more")
                
        except Exception as e:
            print(f"❌ Bandit scanner error: {e}")
        
        print()
        
        # Test Trivy Scanner
        print("🔍 Testing Trivy Scanner...")
        try:
            trivy_config = TrivyConfig()
            trivy_scanner = TrivyScanner(trivy_config)
            trivy_results = await trivy_scanner.scan(str(repo_path))
            
            print(f"✅ Trivy found {len(trivy_results)} dependency vulnerabilities:")
            for vuln in trivy_results[:3]:  # Show first 3
                print(f"  - {vuln.severity.upper()}: {vuln.package_name} {vuln.installed_version} -> {vuln.fixed_version}")
            if len(trivy_results) > 3:
                print(f"  ... and {len(trivy_results) - 3} more")
                
        except Exception as e:
            print(f"❌ Trivy scanner error: {e}")
        
        print()
        
        # Test Secret Scanner
        print("🔍 Testing Secret Scanner...")
        try:
            secret_config = SecretScannerConfig()
            secret_scanner = SecretScanner(secret_config)
            

            
            secret_results = await secret_scanner.scan(str(repo_path))
            
            print(f"✅ Secret scanner found {len(secret_results)} secrets:")
            for secret in secret_results[:3]:  # Show first 3
                print(f"  - {secret.severity.upper()}: {secret.secret_type} in {secret.file}:{secret.line}")
            if len(secret_results) > 3:
                print(f"  ... and {len(secret_results) - 3} more")
                
        except Exception as e:
            print(f"❌ Secret scanner error: {e}")
        
        print()
        print("=" * 60)
        print("Demo completed! Install the security tools to see real results:")
        print("  - pip install bandit")
        print("  - pip install detect-secrets") 
        print("  - Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")


if __name__ == "__main__":
    asyncio.run(demo_scanners())