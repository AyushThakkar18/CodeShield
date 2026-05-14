"""
Repository service for validating, cloning, and managing GitHub repositories.

This service handles:
- GitHub URL validation
- Repository accessibility checks
- Repository cloning with size limits
- Temporary directory management and cleanup
"""

import asyncio
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx
from git import Repo, GitCommandError
from pydantic import BaseModel

from ..models.config import ScanConfig


class RepositoryInfo(BaseModel):
    """Information about a repository."""
    url: str
    owner: str
    name: str
    full_name: str
    is_public: bool
    size_kb: Optional[int] = None


class RepositoryValidationError(Exception):
    """Raised when repository validation fails."""
    pass


class RepositoryCloneError(Exception):
    """Raised when repository cloning fails."""
    pass


class RepositoryService:
    """Service for handling GitHub repository operations."""
    
    def __init__(self):
        self.config = ScanConfig()
        self._temp_dirs = set()  # Track temporary directories for cleanup
    
    def validate_github_url(self, url: str) -> RepositoryInfo:
        """
        Validate a GitHub repository URL and extract repository information.
        
        Args:
            url: GitHub repository URL to validate
            
        Returns:
            RepositoryInfo object with parsed repository details
            
        Raises:
            RepositoryValidationError: If URL is invalid or not a GitHub repository
        """
        if not url or not isinstance(url, str):
            raise RepositoryValidationError("URL must be a non-empty string")
        
        # Clean up the URL - remove trailing slashes and .git suffix
        url = url.strip().rstrip('/').rstrip('.git')
        
        # Parse the URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise RepositoryValidationError(f"Invalid URL format: {e}")
        
        # Check if it's a GitHub URL
        if parsed.netloc.lower() not in ['github.com', 'www.github.com']:
            raise RepositoryValidationError("URL must be a GitHub repository")
        
        # Extract owner and repository name using regex
        path_pattern = r'^/([^/]+)/([^/]+)/?$'
        match = re.match(path_pattern, parsed.path)
        
        if not match:
            raise RepositoryValidationError(
                "Invalid GitHub repository URL format. Expected: https://github.com/owner/repo"
            )
        
        owner, repo_name = match.groups()
        
        # Validate owner and repo name format
        if not self._is_valid_github_name(owner):
            raise RepositoryValidationError(f"Invalid GitHub username: {owner}")
        
        if not self._is_valid_github_name(repo_name):
            raise RepositoryValidationError(f"Invalid GitHub repository name: {repo_name}")
        
        return RepositoryInfo(
            url=f"https://github.com/{owner}/{repo_name}",
            owner=owner,
            name=repo_name,
            full_name=f"{owner}/{repo_name}",
            is_public=True  # Will be verified in check_repository_accessibility
        )
    
    def _is_valid_github_name(self, name: str) -> bool:
        """
        Check if a GitHub username or repository name is valid.
        
        Args:
            name: Name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not name or len(name) > 39:  # GitHub limit
            return False
        
        # GitHub names can contain alphanumeric characters and hyphens
        # Cannot start or end with hyphen
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        return bool(re.match(pattern, name))
    
    async def check_repository_accessibility(self, repo_info: RepositoryInfo) -> RepositoryInfo:
        """
        Check if a repository is accessible and public.
        
        Args:
            repo_info: Repository information to check
            
        Returns:
            Updated RepositoryInfo with accessibility status and size
            
        Raises:
            RepositoryValidationError: If repository is not accessible or private
        """
        api_url = f"https://api.github.com/repos/{repo_info.full_name}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(api_url)
                
                if response.status_code == 404:
                    raise RepositoryValidationError(
                        f"Repository {repo_info.full_name} not found or is private"
                    )
                elif response.status_code == 403:
                    raise RepositoryValidationError(
                        "GitHub API rate limit exceeded. Please try again later."
                    )
                elif response.status_code != 200:
                    raise RepositoryValidationError(
                        f"Failed to access repository: HTTP {response.status_code}"
                    )
                
                repo_data = response.json()
                
                # Check if repository is public
                if repo_data.get('private', True):
                    raise RepositoryValidationError(
                        f"Repository {repo_info.full_name} is private. Only public repositories are supported."
                    )
                
                # Get repository size in KB
                size_kb = repo_data.get('size', 0)
                
                # Check size limit (convert to MB for comparison)
                size_mb = size_kb / 1024
                if size_mb > self.config.max_repo_size_mb:
                    raise RepositoryValidationError(
                        f"Repository size ({size_mb:.1f}MB) exceeds the {self.config.max_repo_size_mb}MB limit"
                    )
                
                # Update repository info
                repo_info.is_public = True
                repo_info.size_kb = size_kb
                
                return repo_info
                
            except httpx.RequestError as e:
                raise RepositoryValidationError(f"Network error accessing GitHub API: {e}")
    
    async def clone_repository(self, repo_info: RepositoryInfo) -> str:
        """
        Clone a repository to a temporary directory.
        
        Args:
            repo_info: Repository information
            
        Returns:
            Path to the cloned repository directory
            
        Raises:
            RepositoryCloneError: If cloning fails
        """
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix=self.config.temp_dir_prefix)
        self._temp_dirs.add(temp_dir)
        
        clone_path = os.path.join(temp_dir, repo_info.name)
        
        try:
            # Clone repository with timeout
            await asyncio.wait_for(
                self._clone_repo_sync(repo_info.url, clone_path),
                timeout=self.config.scan_timeout_minutes * 60
            )
            
            # Verify the clone was successful
            if not os.path.exists(clone_path) or not os.path.isdir(clone_path):
                raise RepositoryCloneError("Repository clone verification failed")
            
            # Check actual size on disk
            actual_size_mb = self._get_directory_size_mb(clone_path)
            if actual_size_mb > self.config.max_repo_size_mb:
                raise RepositoryCloneError(
                    f"Cloned repository size ({actual_size_mb:.1f}MB) exceeds limit"
                )
            
            return clone_path
            
        except asyncio.TimeoutError:
            raise RepositoryCloneError(
                f"Repository cloning timed out after {self.config.scan_timeout_minutes} minutes"
            )
        except GitCommandError as e:
            raise RepositoryCloneError(f"Git clone failed: {e}")
        except Exception as e:
            raise RepositoryCloneError(f"Unexpected error during cloning: {e}")
    
    async def _clone_repo_sync(self, url: str, path: str) -> None:
        """
        Synchronous repository cloning wrapped for async execution.
        
        Args:
            url: Repository URL to clone
            path: Local path to clone to
        """
        def _clone():
            Repo.clone_from(
                url, 
                path, 
                depth=1,  # Shallow clone for faster operation
                single_branch=True  # Only clone default branch
            )
        
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _clone)
    
    def _get_directory_size_mb(self, path: str) -> float:
        """
        Calculate directory size in MB.
        
        Args:
            path: Directory path
            
        Returns:
            Size in MB
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, IOError):
                    # Skip files that can't be accessed
                    continue
        
        return total_size / (1024 * 1024)  # Convert to MB
    
    def cleanup_repository(self, repo_path: str) -> None:
        """
        Clean up a cloned repository and its temporary directory.
        
        Args:
            repo_path: Path to the repository directory to clean up
        """
        try:
            # Find the temporary directory that contains this repo
            temp_dir = None
            for tracked_dir in self._temp_dirs.copy():
                if repo_path.startswith(tracked_dir):
                    temp_dir = tracked_dir
                    break
            
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                self._temp_dirs.discard(temp_dir)
            elif os.path.exists(repo_path):
                # Fallback: just remove the repo directory
                shutil.rmtree(repo_path, ignore_errors=True)
                
        except Exception:
            # Ignore cleanup errors - they're not critical
            pass
    
    def cleanup_all_repositories(self) -> None:
        """Clean up all tracked temporary directories."""
        for temp_dir in self._temp_dirs.copy():
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                self._temp_dirs.discard(temp_dir)
            except Exception:
                # Ignore cleanup errors
                pass
    
    async def validate_and_prepare_repository(self, url: str) -> Tuple[RepositoryInfo, str]:
        """
        Complete workflow: validate URL, check accessibility, and clone repository.
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Tuple of (RepositoryInfo, cloned_path)
            
        Raises:
            RepositoryValidationError: If validation fails
            RepositoryCloneError: If cloning fails
        """
        # Step 1: Validate URL format
        repo_info = self.validate_github_url(url)
        
        # Step 2: Check repository accessibility and get metadata
        repo_info = await self.check_repository_accessibility(repo_info)
        
        # Step 3: Clone repository
        clone_path = await self.clone_repository(repo_info)
        
        return repo_info, clone_path