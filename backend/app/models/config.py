"""
Configuration models for CodeShield security scanning
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class ScanConfig(BaseModel):
    """System-wide scanning configuration"""
    max_repo_size_mb: int = Field(200, ge=1, description="Maximum repository size in MB")
    scan_timeout_minutes: int = Field(5, ge=1, description="Maximum scan duration in minutes")
    temp_dir_prefix: str = Field("codeshield_", description="Prefix for temporary directories")
    cleanup_delay_minutes: int = Field(10, ge=0, description="Delay before cleaning up temporary files")
    max_concurrent_scans: int = Field(5, ge=1, description="Maximum number of concurrent scans")
    
    model_config = ConfigDict(env_prefix="CODESHIELD_")


class BanditConfig(BaseModel):
    """Configuration for Bandit static analysis tool"""
    exclude_dirs: List[str] = Field(
        default_factory=lambda: [".git", "node_modules", "__pycache__", ".venv", "venv"],
        description="Directories to exclude from scanning"
    )
    severity_levels: List[str] = Field(
        default_factory=lambda: ["low", "medium", "high"],
        description="Severity levels to include"
    )
    confidence_levels: List[str] = Field(
        default_factory=lambda: ["low", "medium", "high"],
        description="Confidence levels to include"
    )
    format: str = Field("json", description="Output format")
    recursive: bool = Field(True, description="Scan directories recursively")
    
    @field_validator('severity_levels', 'confidence_levels')
    @classmethod
    def validate_levels(cls, v):
        """Validate that levels contain only valid values"""
        valid_levels = {"low", "medium", "high"}
        if not all(level in valid_levels for level in v):
            raise ValueError(f"Levels must be from: {valid_levels}")
        return v


class TrivyConfig(BaseModel):
    """Configuration for Trivy vulnerability scanner"""
    scan_types: List[str] = Field(
        default_factory=lambda: ["vuln", "secret", "config"],
        description="Types of scans to perform"
    )
    severity_levels: List[str] = Field(
        default_factory=lambda: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        description="Severity levels to include"
    )
    format: str = Field("json", description="Output format")
    timeout: str = Field("5m", description="Scan timeout")
    skip_dirs: List[str] = Field(
        default_factory=lambda: [".git", "node_modules", "__pycache__"],
        description="Directories to skip"
    )
    
    @field_validator('scan_types')
    @classmethod
    def validate_scan_types(cls, v):
        """Validate scan types"""
        valid_types = {"vuln", "secret", "config", "license"}
        if not all(scan_type in valid_types for scan_type in v):
            raise ValueError(f"Scan types must be from: {valid_types}")
        return v
    
    @field_validator('severity_levels')
    @classmethod
    def validate_severity_levels(cls, v):
        """Validate severity levels"""
        valid_levels = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if not all(level in valid_levels for level in v):
            raise ValueError(f"Severity levels must be from: {valid_levels}")
        return v


class SecretScannerConfig(BaseModel):
    """Configuration for secret detection scanner"""
    plugins: List[str] = Field(
        default_factory=lambda: [
            "ArtifactoryDetector",
            "AWSKeyDetector", 
            "Base64HighEntropyString",
            "BasicAuthDetector",
            "GitHubTokenDetector",
            "HexHighEntropyString",
            "JwtTokenDetector",
            "KeywordDetector",
            "PrivateKeyDetector",
            "SlackDetector"
        ],
        description="Secret detection plugins to use"
    )
    exclude_files: List[str] = Field(
        default_factory=lambda: ["*.pyc", "*.git*", "*.lock", "*.log"],
        description="File patterns to exclude"
    )
    exclude_lines: List[str] = Field(
        default_factory=lambda: ["password.*=.*example", "key.*=.*test"],
        description="Line patterns to exclude (regex)"
    )
    word_list_file: Optional[str] = Field(None, description="Path to custom word list file")
    entropy_threshold: float = Field(4.5, ge=0.0, le=8.0, description="Entropy threshold for detection")


class SecurityToolsConfig(BaseModel):
    """Combined configuration for all security tools"""
    bandit: BanditConfig = Field(default_factory=BanditConfig, description="Bandit configuration")
    trivy: TrivyConfig = Field(default_factory=TrivyConfig, description="Trivy configuration")
    secret_scanner: SecretScannerConfig = Field(default_factory=SecretScannerConfig, description="Secret scanner configuration")


class AppConfig(BaseModel):
    """Main application configuration"""
    scan: ScanConfig = Field(default_factory=ScanConfig, description="Scan configuration")
    security_tools: SecurityToolsConfig = Field(default_factory=SecurityToolsConfig, description="Security tools configuration")
    
    # API Configuration
    api_title: str = Field("CodeShield Security Scanner", description="API title")
    api_version: str = Field("1.0.0", description="API version")
    api_description: str = Field("Security scanning service for GitHub repositories", description="API description")
    
    # CORS Configuration
    cors_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins"
    )
    
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")