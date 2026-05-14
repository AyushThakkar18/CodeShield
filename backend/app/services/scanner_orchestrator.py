"""
Scanner orchestration service for coordinating parallel security scans
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from uuid import uuid4

from ..models.scan import (
    ScanResults, ScanSummary, Vulnerability, 
    DependencyVulnerability, SecretFinding
)
from ..models.config import SecurityToolsConfig
from .scanners import BanditScanner, TrivyScanner, SecretScanner


logger = logging.getLogger(__name__)


class ScannerService:
    """
    Orchestrates parallel execution of all security scanners and aggregates results
    """
    
    def __init__(self, config: SecurityToolsConfig):
        """Initialize scanner service with configuration"""
        self.config = config
        self.bandit_scanner = BanditScanner(config.bandit)
        self.trivy_scanner = TrivyScanner(config.trivy)
        self.secret_scanner = SecretScanner(config.secret_scanner)
        
        # Retry configuration
        self.max_retries = 1
        self.retry_delay = 2.0  # seconds
    
    async def scan_repository(
        self, 
        repo_path: str, 
        repository_url: str,
        scan_id: Optional[str] = None
    ) -> ScanResults:
        """
        Perform comprehensive security scan on repository
        
        Args:
            repo_path: Path to cloned repository
            repository_url: Original repository URL
            scan_id: Optional scan identifier
            
        Returns:
            Complete scan results with aggregated findings
        """
        if scan_id is None:
            scan_id = str(uuid4())
        
        start_time = time.time()
        scan_date = datetime.now()
        
        logger.info(f"Starting comprehensive scan for {repository_url} (ID: {scan_id})")
        
        try:
            # Execute all scanners in parallel with retry logic
            scan_tasks = [
                self._run_scanner_with_retry("bandit", self.bandit_scanner, repo_path),
                self._run_scanner_with_retry("trivy", self.trivy_scanner, repo_path),
                self._run_scanner_with_retry("secrets", self.secret_scanner, repo_path)
            ]
            
            # Wait for all scanners to complete
            scanner_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results and handle any failures
            bandit_results, trivy_results, secret_results = self._process_scanner_results(
                scanner_results
            )
            
            # Aggregate all results
            aggregated_results = self._aggregate_results(
                bandit_results, trivy_results, secret_results
            )
            
            # Calculate scan duration
            scan_duration = time.time() - start_time
            
            # Determine overall scan status
            scan_status = self._determine_scan_status(scanner_results)
            
            # Create comprehensive scan results
            scan_results = ScanResults(
                scan_id=scan_id,
                repository_url=repository_url,
                scan_date=scan_date,
                summary=self._calculate_summary(aggregated_results),
                static_analysis=aggregated_results["static_analysis"],
                dependencies=aggregated_results["dependencies"],
                secrets=aggregated_results["secrets"],
                scan_duration=scan_duration,
                status=scan_status
            )
            
            logger.info(
                f"Scan completed for {repository_url} in {scan_duration:.2f}s. "
                f"Found {scan_results.summary.total} total issues"
            )
            
            return scan_results
            
        except Exception as e:
            scan_duration = time.time() - start_time
            logger.error(f"Scan failed for {repository_url}: {str(e)}")
            
            # Return failed scan results
            return ScanResults(
                scan_id=scan_id,
                repository_url=repository_url,
                scan_date=scan_date,
                summary=ScanSummary(),
                static_analysis=[],
                dependencies=[],
                secrets=[],
                scan_duration=scan_duration,
                status="failed"
            )
    
    async def _run_scanner_with_retry(
        self, 
        scanner_name: str, 
        scanner: Any, 
        repo_path: str
    ) -> Tuple[str, List[Any]]:
        """
        Run a scanner with retry logic
        
        Args:
            scanner_name: Name of the scanner for logging
            scanner: Scanner instance to run
            repo_path: Path to repository
            
        Returns:
            Tuple of (scanner_name, results)
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                logger.debug(f"Running {scanner_name} scanner (attempt {attempt + 1})")
                results = await scanner.scan(repo_path)
                logger.info(f"{scanner_name} scanner completed successfully with {len(results)} findings")
                return (scanner_name, results)
                
            except Exception as e:
                last_exception = e
                logger.warning(
                    f"{scanner_name} scanner failed on attempt {attempt + 1}: {str(e)}"
                )
                
                if attempt < self.max_retries:
                    logger.info(f"Retrying {scanner_name} scanner in {self.retry_delay}s...")
                    await asyncio.sleep(self.retry_delay)
                else:
                    logger.error(f"{scanner_name} scanner failed after {self.max_retries + 1} attempts")
        
        # If we get here, all retries failed
        raise RuntimeError(f"{scanner_name} scanner failed: {str(last_exception)}")
    
    def _process_scanner_results(
        self, 
        scanner_results: List[Any]
    ) -> Tuple[List[Vulnerability], List[DependencyVulnerability], List[SecretFinding]]:
        """
        Process scanner results and handle exceptions
        
        Args:
            scanner_results: Results from asyncio.gather with return_exceptions=True
            
        Returns:
            Tuple of (bandit_results, trivy_results, secret_results)
        """
        bandit_results = []
        trivy_results = []
        secret_results = []
        
        for i, result in enumerate(scanner_results):
            scanner_names = ["bandit", "trivy", "secrets"]
            scanner_name = scanner_names[i]
            
            if isinstance(result, Exception):
                logger.error(f"{scanner_name} scanner failed: {str(result)}")
                # Continue with empty results for this scanner
                continue
            
            # Unpack the result tuple
            name, findings = result
            
            if name == "bandit":
                bandit_results = findings
            elif name == "trivy":
                trivy_results = findings
            elif name == "secrets":
                secret_results = findings
        
        return bandit_results, trivy_results, secret_results
    
    def _aggregate_results(
        self,
        bandit_results: List[Vulnerability],
        trivy_results: List[DependencyVulnerability], 
        secret_results: List[SecretFinding]
    ) -> Dict[str, List[Any]]:
        """
        Aggregate results from all scanners
        
        Args:
            bandit_results: Static analysis vulnerabilities
            trivy_results: Dependency vulnerabilities
            secret_results: Secret findings
            
        Returns:
            Dictionary with aggregated results by category
        """
        # Apply severity categorization and deduplication
        categorized_static = self._categorize_by_severity(bandit_results)
        categorized_deps = self._categorize_by_severity(trivy_results)
        categorized_secrets = self._categorize_by_severity(secret_results)
        
        # Remove duplicates within each category
        deduplicated_static = self._deduplicate_findings(categorized_static)
        deduplicated_deps = self._deduplicate_findings(categorized_deps)
        deduplicated_secrets = self._deduplicate_findings(categorized_secrets)
        
        return {
            "static_analysis": deduplicated_static,
            "dependencies": deduplicated_deps,
            "secrets": deduplicated_secrets
        }
    
    def _categorize_by_severity(self, findings: List[Any]) -> List[Any]:
        """
        Ensure consistent severity categorization across all findings
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of findings with normalized severity levels
        """
        severity_map = {
            "critical": "critical",
            "high": "high", 
            "medium": "medium",
            "low": "low",
            # Handle any inconsistent casing
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium", 
            "LOW": "low"
        }
        
        for finding in findings:
            if hasattr(finding, 'severity'):
                finding.severity = severity_map.get(finding.severity, "low")
        
        return findings
    
    def _deduplicate_findings(self, findings: List[Any]) -> List[Any]:
        """
        Remove duplicate findings based on file, line, and vulnerability type
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of deduplicated findings
        """
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create a unique key for deduplication
            key = (
                finding.file,
                finding.line or 0,
                finding.title,
                finding.tool
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
            else:
                logger.debug(f"Duplicate finding removed: {finding.title} in {finding.file}")
        
        return deduplicated
    
    def _calculate_summary(self, aggregated_results: Dict[str, List[Any]]) -> ScanSummary:
        """
        Calculate summary statistics for all findings
        
        Args:
            aggregated_results: Aggregated scan results
            
        Returns:
            Summary statistics
        """
        all_findings = (
            aggregated_results["static_analysis"] +
            aggregated_results["dependencies"] + 
            aggregated_results["secrets"]
        )
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for finding in all_findings:
            severity = getattr(finding, 'severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return ScanSummary(
            critical=severity_counts["critical"],
            high=severity_counts["high"],
            medium=severity_counts["medium"],
            low=severity_counts["low"]
        )
    
    def _determine_scan_status(self, scanner_results: List[Any]) -> str:
        """
        Determine overall scan status based on individual scanner results
        
        Args:
            scanner_results: Results from all scanners
            
        Returns:
            Overall scan status: 'completed', 'partial', or 'failed'
        """
        failed_count = sum(1 for result in scanner_results if isinstance(result, Exception))
        total_scanners = len(scanner_results)
        
        if failed_count == 0:
            return "completed"
        elif failed_count < total_scanners:
            return "partial"
        else:
            return "failed"
    
    async def get_scanner_status(self) -> Dict[str, bool]:
        """
        Check the availability status of all scanners
        
        Returns:
            Dictionary mapping scanner names to availability status
        """
        status = {}
        
        # Test each scanner with a minimal operation
        try:
            # For Bandit, we can check if the module is importable
            import bandit
            status["bandit"] = True
        except ImportError:
            status["bandit"] = False
        
        try:
            # For Trivy, we can try to run --version
            process = await asyncio.create_subprocess_exec(
                "trivy", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            status["trivy"] = process.returncode == 0
        except (FileNotFoundError, Exception):
            status["trivy"] = False
        
        try:
            # For detect-secrets, check if module is importable
            import detect_secrets
            status["detect-secrets"] = True
        except ImportError:
            status["detect-secrets"] = False
        
        return status