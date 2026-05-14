#!/usr/bin/env python3
"""
GitHub Repository Security Scanner

This script scans a GitHub repository for security vulnerabilities and generates reports.

Usage:
    python scan_github_repo.py <github_url>
    python scan_github_repo.py https://github.com/user/repo

Examples:
    python scan_github_repo.py https://github.com/we45/Vulnerable-Flask-App
    python scan_github_repo.py https://github.com/pallets/flask
"""

import sys
import asyncio
import argparse
import logging
import warnings
from pathlib import Path
from datetime import datetime

from app.services.scanner_orchestrator import ScannerService
from app.services.report import ReportService
from app.services.repository import RepositoryService, RepositoryValidationError, RepositoryCloneError
from app.models.config import SecurityToolsConfig


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Scan a GitHub repository for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://github.com/we45/Vulnerable-Flask-App
  %(prog)s https://github.com/pallets/flask
  %(prog)s https://github.com/your-username/your-repo
        """
    )
    
    parser.add_argument(
        'github_url',
        help='GitHub repository URL to scan (e.g., https://github.com/user/repo)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Directory to save reports (default: current directory)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'pdf', 'both'],
        default='both',
        help='Report format to generate (default: both)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def validate_github_url(url):
    """Validate that the URL is a GitHub repository URL"""
    if not url.startswith('https://github.com/'):
        raise ValueError("URL must be a GitHub repository URL (https://github.com/user/repo)")
    
    parts = url.replace('https://github.com/', '').split('/')
    if len(parts) < 2:
        raise ValueError("Invalid GitHub URL format. Expected: https://github.com/user/repo")
    
    return url


def configure_logging(verbose: bool = False):
    """Configure logging to suppress unwanted warnings"""
    # Suppress WeasyPrint warnings
    warnings.filterwarnings("ignore", message=".*WeasyPrint.*")
    
    # Configure logging levels
    if not verbose:
        # Suppress WeasyPrint and other library warnings
        logging.getLogger("weasyprint").setLevel(logging.ERROR)
        logging.getLogger("fontTools").setLevel(logging.ERROR)
        logging.getLogger("cffi").setLevel(logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.getLogger().setLevel(logging.INFO)


async def main():
    """Main function to scan repository and generate reports"""
    args = parse_arguments()
    
    # Configure logging to suppress warnings
    configure_logging(args.verbose)
    
    print("🔍 CodeShield GitHub Repository Scanner")
    print("=" * 50)
    
    try:
        # Validate GitHub URL
        github_url = validate_github_url(args.github_url)
        print(f"📂 Repository: {github_url}")
        
        # Extract repo name for file naming
        repo_name = github_url.split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        
        # Initialize services
        print("\n🔧 Initializing services...")
        config = SecurityToolsConfig()
        repo_service = RepositoryService()
        scanner_service = ScannerService(config)
        report_service = ReportService()
        
        if args.verbose:
            print("   ✓ Repository service (cloning)")
            print("   ✓ Bandit (Python static analysis)")
            print("   ✓ Trivy (dependency vulnerabilities)")
            print("   ✓ detect-secrets (secret detection)")
        
        # Validate and check repository
        print(f"\n🔍 Validating repository access...")
        repo_info = repo_service.validate_github_url(github_url)
        print(f"   📂 Repository: {repo_info.full_name}")
        
        # Check accessibility
        repo_info = await repo_service.check_repository_accessibility(repo_info)
        if args.verbose:
            print(f"   ✓ Repository is accessible")
            if repo_info.size_kb:
                print(f"   📏 Repository size: {repo_info.size_kb / 1024:.1f} MB")
        
        # Clone repository
        print(f"\n📥 Cloning repository...")
        repo_path = await repo_service.clone_repository(repo_info)
        print(f"   ✓ Repository cloned to: {repo_path}")
        
        # Start scanning
        print(f"\n🚀 Starting security scan of {repo_name}...")
        print("   This may take a few minutes depending on repository size...")
        
        start_time = datetime.now()
        
        try:
            # Run the comprehensive scan
            scan_results = await scanner_service.scan_repository(repo_path, github_url)
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            print(f"\n✅ Scan completed in {scan_duration:.1f} seconds")
            
            # Display summary
            print(f"\n📊 Scan Results Summary:")
            print(f"   🔴 Critical: {scan_results.summary.critical}")
            print(f"   🟠 High: {scan_results.summary.high}")
            print(f"   🟡 Medium: {scan_results.summary.medium}")
            print(f"   🟢 Low: {scan_results.summary.low}")
            print(f"   📈 Total: {scan_results.summary.total}")
            
            print(f"\n📋 Finding Breakdown:")
            print(f"   🔍 Static Analysis: {len(scan_results.static_analysis)}")
            print(f"   📦 Dependencies: {len(scan_results.dependencies)}")
            print(f"   🔐 Secrets: {len(scan_results.secrets)}")
            
            # Generate reports
            output_dir = Path(args.output_dir)
            output_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"{repo_name}_security_report_{timestamp}"
            
            print(f"\n📄 Generating reports...")
            
            # Generate JSON report
            if args.format in ['json', 'both']:
                json_path = output_dir / f"{base_filename}.json"
                report_service.save_json_report(scan_results, json_path)
                print(f"   ✅ JSON report: {json_path.absolute()}")
                print(f"      📏 Size: {json_path.stat().st_size} bytes")
            
            # Generate PDF report (with fallback)
            if args.format in ['pdf', 'both']:
                print(f"   📑 Attempting PDF generation...")
                try:
                    pdf_path = output_dir / f"{base_filename}.pdf"
                    report_service.save_pdf_report(scan_results, pdf_path)
                    print(f"   ✅ PDF report: {pdf_path.absolute()}")
                    print(f"      📏 Size: {pdf_path.stat().st_size} bytes")
                except RuntimeError as e:
                    print(f"   ⚠️  PDF generation failed: {e}")
                    print(f"   🔄 Generating fallback JSON...")
                    
                    fallback_bytes = report_service.generate_report_with_fallback(scan_results, "pdf")
                    fallback_path = output_dir / f"{base_filename}_fallback.json"
                    with open(fallback_path, 'wb') as f:
                        f.write(fallback_bytes)
                    print(f"   ✅ Fallback JSON: {fallback_path.absolute()}")
            
            # Show recommendations if there are findings
            if scan_results.summary.total > 0:
                json_report = report_service.generate_json_report(scan_results)
                recommendations = json_report["recommendations"]
                
                print(f"\n💡 Key Recommendations:")
                if recommendations["priority_actions"]:
                    for i, action in enumerate(recommendations["priority_actions"][:3], 1):
                        print(f"   {i}. {action}")
                
                if scan_results.summary.critical > 0 or scan_results.summary.high > 0:
                    print(f"\n⚠️  High Priority: Address critical and high-severity vulnerabilities immediately!")
            else:
                print(f"\n🎉 Great! No security vulnerabilities found in this repository.")
            
            print(f"\n✨ Scan and report generation completed successfully!")
            
        except Exception as scan_error:
            print(f"\n❌ Scan failed: {scan_error}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            # Clean up cloned repository
            if 'repo_path' in locals():
                try:
                    repo_service.cleanup_repository(repo_path)
                    if args.verbose:
                        print(f"   🧹 Cleaned up temporary files")
                except Exception as cleanup_error:
                    if args.verbose:
                        print(f"   ⚠️  Cleanup warning: {cleanup_error}")
            
    except (ValueError, RepositoryValidationError, RepositoryCloneError) as e:
        print(f"\n❌ Repository error: {e}")
        return 1
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Error: GitHub URL is required")
        print("\nUsage:")
        print("  python scan_github_repo.py <github_url>")
        print("\nExample:")
        print("  python scan_github_repo.py https://github.com/we45/Vulnerable-Flask-App")
        sys.exit(1)
    
    # Run the async main function
    exit_code = asyncio.run(main())
    sys.exit(exit_code)