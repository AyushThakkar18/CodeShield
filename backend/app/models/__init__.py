"""
Models package for CodeShield security scanner
"""

from .scan import (
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

from .config import (
    ScanConfig,
    BanditConfig,
    TrivyConfig,
    SecretScannerConfig,
    SecurityToolsConfig,
    AppConfig
)

__all__ = [
    # Scan models
    "ScanRequest",
    "ScanResponse", 
    "Vulnerability",
    "DependencyVulnerability",
    "SecretFinding",
    "ScanSummary",
    "ScanResults",
    "ScanStatus",
    "ErrorDetail",
    "ErrorResponse",
    
    # Configuration models
    "ScanConfig",
    "BanditConfig",
    "TrivyConfig", 
    "SecretScannerConfig",
    "SecurityToolsConfig",
    "AppConfig"
]