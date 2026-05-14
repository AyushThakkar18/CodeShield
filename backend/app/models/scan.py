"""
Core data models for CodeShield security scanning using Pydantic
"""

from datetime import datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


class ScanRequest(BaseModel):
    """Request model for initiating a repository scan"""
    repository_url: HttpUrl = Field(..., description="GitHub repository URL to scan")
    
    @field_validator('repository_url')
    @classmethod
    def validate_github_url(cls, v):
        """Ensure the URL is a GitHub repository URL"""
        if not str(v).startswith('https://github.com/'):
            raise ValueError('Only GitHub repository URLs are supported')
        return v


class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    scan_id: str = Field(..., description="Unique identifier for the scan")
    status: str = Field(..., description="Current scan status")


class Vulnerability(BaseModel):
    """Base vulnerability model"""
    tool: Literal['bandit', 'trivy', 'detect-secrets'] = Field(..., description="Security tool that found the vulnerability")
    file: str = Field(..., description="File path where vulnerability was found")
    line: Optional[int] = Field(None, description="Line number of the vulnerability")
    severity: Literal['critical', 'high', 'medium', 'low'] = Field(..., description="Severity level")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    recommendation: str = Field(..., description="Fix recommendation")
    cve_id: Optional[str] = Field(None, description="CVE identifier if applicable")
    confidence: Optional[Literal['high', 'medium', 'low']] = Field(None, description="Confidence level")


class DependencyVulnerability(Vulnerability):
    """Dependency-specific vulnerability model"""
    package_name: str = Field(..., description="Name of the vulnerable package")
    installed_version: str = Field(..., description="Currently installed version")
    fixed_version: Optional[str] = Field(None, description="Version that fixes the vulnerability")
    cve_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVE score (0-10)")


class SecretFinding(Vulnerability):
    """Secret detection finding model"""
    secret_type: str = Field(..., description="Type of secret detected")
    entropy: Optional[float] = Field(None, ge=0.0, description="Entropy score of the secret")
    is_verified: Optional[bool] = Field(None, description="Whether the secret was verified as active")


class ScanSummary(BaseModel):
    """Summary statistics for scan results"""
    critical: int = Field(0, ge=0, description="Number of critical vulnerabilities")
    high: int = Field(0, ge=0, description="Number of high severity vulnerabilities")
    medium: int = Field(0, ge=0, description="Number of medium severity vulnerabilities")
    low: int = Field(0, ge=0, description="Number of low severity vulnerabilities")
    total: int = Field(0, ge=0, description="Total number of vulnerabilities")
    
    @model_validator(mode='after')
    def calculate_total(self):
        """Automatically calculate total from individual counts"""
        self.total = self.critical + self.high + self.medium + self.low
        return self


class ScanResults(BaseModel):
    """Complete scan results model"""
    scan_id: str = Field(..., description="Unique scan identifier")
    repository_url: HttpUrl = Field(..., description="Scanned repository URL")
    scan_date: datetime = Field(..., description="When the scan was performed")
    summary: ScanSummary = Field(..., description="Summary statistics")
    static_analysis: List[Vulnerability] = Field(default_factory=list, description="Static analysis findings")
    dependencies: List[DependencyVulnerability] = Field(default_factory=list, description="Dependency vulnerabilities")
    secrets: List[SecretFinding] = Field(default_factory=list, description="Secret detection findings")
    scan_duration: float = Field(..., ge=0, description="Scan duration in seconds")
    status: Literal['completed', 'failed', 'partial'] = Field(..., description="Scan completion status")


class ScanStatus(BaseModel):
    """Scan progress status model"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: Literal['initiated', 'cloning', 'scanning', 'completed', 'failed'] = Field(..., description="Current status")
    progress: int = Field(..., ge=0, le=100, description="Progress percentage")
    current_operation: Optional[str] = Field(None, description="Current operation being performed")
    estimated_time_remaining: Optional[int] = Field(None, ge=0, description="Estimated seconds remaining")


class ErrorDetail(BaseModel):
    """Error response detail model"""
    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    suggestions: Optional[List[str]] = Field(None, description="Suggested actions")


class ErrorResponse(BaseModel):
    """Error response model"""
    error: ErrorDetail = Field(..., description="Error information")