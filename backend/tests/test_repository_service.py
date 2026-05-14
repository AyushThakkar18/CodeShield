"""
Unit tests for RepositoryService
"""

import asyncio
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from pathlib import Path

import pytest
import httpx
from git import GitCommandError

from app.services.repository import (
    RepositoryService,
    RepositoryInfo,
    RepositoryValidationError,
    RepositoryCloneError
)


class TestRepositoryService:
    """Test cases for RepositoryService"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = RepositoryService()
    
    def teardown_method(self):
        """Clean up after tests"""
        self.service.cleanup_all_repositories()


class TestURLValidation:
    """Test cases for GitHub URL validation"""
    
    def setup_method(self):
        self.service = RepositoryService()
    
    def test_validate_github_url_success(self):
        """Test successful URL validation"""
        url = "https://github.com/owner/repo"
        result = self.service.validate_github_url(url)
        
        assert result.url == "https://github.com/owner/repo"
        assert result.owner == "owner"
        assert result.name == "repo"
        assert result.full_name == "owner/repo"
        assert result.is_public is True
    
    def test_validate_github_url_with_trailing_slash(self):
        """Test URL validation with trailing slash"""
        url = "https://github.com/owner/repo/"
        result = self.service.validate_github_url(url)
        
        assert result.url == "https://github.com/owner/repo"
        assert result.owner == "owner"
        assert result.name == "repo"
    
    def test_validate_github_url_with_git_suffix(self):
        """Test URL validation with .git suffix"""
        url = "https://github.com/owner/repo.git"
        result = self.service.validate_github_url(url)
        
        assert result.url == "https://github.com/owner/repo"
        assert result.owner == "owner"
        assert result.name == "repo"
    
    def test_validate_github_url_with_www(self):
        """Test URL validation with www prefix"""
        url = "https://www.github.com/owner/repo"
        result = self.service.validate_github_url(url)
        
        assert result.url == "https://github.com/owner/repo"
        assert result.owner == "owner"
        assert result.name == "repo"
    
    def test_validate_github_url_empty_string(self):
        """Test validation with empty string"""
        with pytest.raises(RepositoryValidationError, match="URL must be a non-empty string"):
            self.service.validate_github_url("")
    
    def test_validate_github_url_none(self):
        """Test validation with None"""
        with pytest.raises(RepositoryValidationError, match="URL must be a non-empty string"):
            self.service.validate_github_url(None)
    
    def test_validate_github_url_invalid_format(self):
        """Test validation with invalid URL format"""
        with pytest.raises(RepositoryValidationError, match="Invalid URL format"):
            self.service.validate_github_url("not-a-url")
    
    def test_validate_github_url_non_github_domain(self):
        """Test validation with non-GitHub domain"""
        with pytest.raises(RepositoryValidationError, match="URL must be a GitHub repository"):
            self.service.validate_github_url("https://gitlab.com/owner/repo")
    
    def test_validate_github_url_invalid_path_format(self):
        """Test validation with invalid path format"""
        with pytest.raises(RepositoryValidationError, match="Invalid GitHub repository URL format"):
            self.service.validate_github_url("https://github.com/owner")
    
    def test_validate_github_url_invalid_path_too_many_segments(self):
        """Test validation with too many path segments"""
        with pytest.raises(RepositoryValidationError, match="Invalid GitHub repository URL format"):
            self.service.validate_github_url("https://github.com/owner/repo/extra/path")
    
    def test_validate_github_url_invalid_owner_name(self):
        """Test validation with invalid owner name"""
        with pytest.raises(RepositoryValidationError, match="Invalid GitHub username"):
            self.service.validate_github_url("https://github.com/-invalid-owner/repo")
    
    def test_validate_github_url_invalid_repo_name(self):
        """Test validation with invalid repository name"""
        with pytest.raises(RepositoryValidationError, match="Invalid GitHub repository name"):
            self.service.validate_github_url("https://github.com/owner/-invalid-repo")
    
    def test_validate_github_url_owner_name_too_long(self):
        """Test validation with owner name too long"""
        long_name = "a" * 40  # GitHub limit is 39 characters
        with pytest.raises(RepositoryValidationError, match="Invalid GitHub username"):
            self.service.validate_github_url(f"https://github.com/{long_name}/repo")
    
    def test_is_valid_github_name_valid_cases(self):
        """Test valid GitHub name cases"""
        valid_names = [
            "owner",
            "owner-name",
            "owner123",
            "123owner",
            "a",
            "a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z-1-2-3-4-5-6-7-8-9"
        ]
        
        for name in valid_names:
            assert self.service._is_valid_github_name(name), f"Name should be valid: {name}"
    
    def test_is_valid_github_name_invalid_cases(self):
        """Test invalid GitHub name cases"""
        invalid_names = [
            "",
            "-owner",  # starts with hyphen
            "owner-",  # ends with hyphen
            "owner..name",  # contains dots
            "owner name",  # contains space
            "owner@name",  # contains special character
            "a" * 40,  # too long
        ]
        
        for name in invalid_names:
            assert not self.service._is_valid_github_name(name), f"Name should be invalid: {name}"


class TestRepositoryAccessibility:
    """Test cases for repository accessibility checks"""
    
    def setup_method(self):
        self.service = RepositoryService()
        self.repo_info = RepositoryInfo(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
            full_name="owner/repo",
            is_public=True
        )
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_success(self):
        """Test successful repository accessibility check"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": False,
            "size": 1024  # 1MB in KB
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            result = await self.service.check_repository_accessibility(self.repo_info)
            
            assert result.is_public is True
            assert result.size_kb == 1024
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_not_found(self):
        """Test repository not found (404)"""
        mock_response = Mock()
        mock_response.status_code = 404
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="Repository .* not found or is private"):
                await self.service.check_repository_accessibility(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_rate_limit(self):
        """Test GitHub API rate limit (403)"""
        mock_response = Mock()
        mock_response.status_code = 403
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="GitHub API rate limit exceeded"):
                await self.service.check_repository_accessibility(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_other_error(self):
        """Test other HTTP error codes"""
        mock_response = Mock()
        mock_response.status_code = 500
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="Failed to access repository: HTTP 500"):
                await self.service.check_repository_accessibility(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_private_repo(self):
        """Test private repository detection"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": True,
            "size": 1024
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="Repository .* is private"):
                await self.service.check_repository_accessibility(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_too_large(self):
        """Test repository size limit enforcement"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": False,
            "size": 300 * 1024  # 300MB in KB, exceeds 200MB limit
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="Repository size .* exceeds the .* limit"):
                await self.service.check_repository_accessibility(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_check_repository_accessibility_network_error(self):
        """Test network error handling"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.RequestError("Network error")
            )
            
            with pytest.raises(RepositoryValidationError, match="Network error accessing GitHub API"):
                await self.service.check_repository_accessibility(self.repo_info)


class TestRepositoryCloning:
    """Test cases for repository cloning"""
    
    def setup_method(self):
        self.service = RepositoryService()
        self.repo_info = RepositoryInfo(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
            full_name="owner/repo",
            is_public=True,
            size_kb=1024
        )
    
    def teardown_method(self):
        self.service.cleanup_all_repositories()
    
    @pytest.mark.asyncio
    async def test_clone_repository_success(self):
        """Test successful repository cloning"""
        with patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone, \
             patch("os.path.exists") as mock_exists, \
             patch("os.path.isdir") as mock_isdir, \
             patch.object(self.service, "_get_directory_size_mb") as mock_size:
            
            mock_temp_dir = "/tmp/codeshield_test123"
            mock_clone_path = f"{mock_temp_dir}/repo"
            
            mock_mkdtemp.return_value = mock_temp_dir
            mock_clone.return_value = None
            mock_exists.return_value = True
            mock_isdir.return_value = True
            mock_size.return_value = 50.0  # 50MB, within limit
            
            result = await self.service.clone_repository(self.repo_info)
            
            assert result == mock_clone_path
            assert mock_temp_dir in self.service._temp_dirs
            mock_clone.assert_called_once_with(self.repo_info.url, mock_clone_path)
    
    @pytest.mark.asyncio
    async def test_clone_repository_timeout(self):
        """Test repository cloning timeout"""
        with patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone:
            
            mock_mkdtemp.return_value = "/tmp/codeshield_test123"
            mock_clone.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(RepositoryCloneError, match="Repository cloning timed out"):
                await self.service.clone_repository(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_clone_repository_git_error(self):
        """Test Git command error during cloning"""
        with patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone:
            
            mock_mkdtemp.return_value = "/tmp/codeshield_test123"
            mock_clone.side_effect = GitCommandError("git clone", 128, "Repository not found")
            
            with pytest.raises(RepositoryCloneError, match="Git clone failed"):
                await self.service.clone_repository(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_clone_repository_verification_failed(self):
        """Test clone verification failure"""
        with patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone, \
             patch("os.path.exists") as mock_exists:
            
            mock_mkdtemp.return_value = "/tmp/codeshield_test123"
            mock_clone.return_value = None
            mock_exists.return_value = False  # Clone verification fails
            
            with pytest.raises(RepositoryCloneError, match="Repository clone verification failed"):
                await self.service.clone_repository(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_clone_repository_size_exceeded_after_clone(self):
        """Test size limit exceeded after cloning"""
        with patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone, \
             patch("os.path.exists") as mock_exists, \
             patch("os.path.isdir") as mock_isdir, \
             patch.object(self.service, "_get_directory_size_mb") as mock_size:
            
            mock_mkdtemp.return_value = "/tmp/codeshield_test123"
            mock_clone.return_value = None
            mock_exists.return_value = True
            mock_isdir.return_value = True
            mock_size.return_value = 250.0  # 250MB, exceeds 200MB limit
            
            with pytest.raises(RepositoryCloneError, match="Cloned repository size .* exceeds limit"):
                await self.service.clone_repository(self.repo_info)
    
    @pytest.mark.asyncio
    async def test_clone_repo_sync(self):
        """Test synchronous clone wrapper"""
        with patch("git.Repo.clone_from") as mock_clone_from:
            await self.service._clone_repo_sync("https://github.com/owner/repo", "/tmp/repo")
            
            mock_clone_from.assert_called_once_with(
                "https://github.com/owner/repo",
                "/tmp/repo",
                depth=1,
                single_branch=True
            )
    
    def test_get_directory_size_mb(self):
        """Test directory size calculation"""
        # Create a temporary directory with some files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_file1 = os.path.join(temp_dir, "file1.txt")
            test_file2 = os.path.join(temp_dir, "file2.txt")
            
            with open(test_file1, "w") as f:
                f.write("x" * 1024)  # 1KB
            
            with open(test_file2, "w") as f:
                f.write("x" * 2048)  # 2KB
            
            size_mb = self.service._get_directory_size_mb(temp_dir)
            
            # Should be approximately 3KB = 0.003MB
            assert 0.002 < size_mb < 0.004
    
    def test_get_directory_size_mb_with_subdirectories(self):
        """Test directory size calculation with subdirectories"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create subdirectory
            sub_dir = os.path.join(temp_dir, "subdir")
            os.makedirs(sub_dir)
            
            # Create files in main and subdirectory
            with open(os.path.join(temp_dir, "file1.txt"), "w") as f:
                f.write("x" * 1024)  # 1KB
            
            with open(os.path.join(sub_dir, "file2.txt"), "w") as f:
                f.write("x" * 1024)  # 1KB
            
            size_mb = self.service._get_directory_size_mb(temp_dir)
            
            # Should be approximately 2KB = 0.002MB
            assert 0.001 < size_mb < 0.003


class TestRepositoryCleanup:
    """Test cases for repository cleanup"""
    
    def setup_method(self):
        self.service = RepositoryService()
    
    def test_cleanup_repository_success(self):
        """Test successful repository cleanup"""
        # Create a temporary directory to simulate a cloned repo
        temp_dir = tempfile.mkdtemp(prefix="codeshield_test_")
        repo_path = os.path.join(temp_dir, "repo")
        os.makedirs(repo_path)
        
        # Add to tracked directories
        self.service._temp_dirs.add(temp_dir)
        
        # Create a test file
        test_file = os.path.join(repo_path, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")
        
        assert os.path.exists(temp_dir)
        assert os.path.exists(repo_path)
        assert os.path.exists(test_file)
        
        # Cleanup
        self.service.cleanup_repository(repo_path)
        
        # Verify cleanup
        assert not os.path.exists(temp_dir)
        assert temp_dir not in self.service._temp_dirs
    
    def test_cleanup_repository_not_tracked(self):
        """Test cleanup of repository not in tracked directories"""
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="codeshield_test_")
        repo_path = os.path.join(temp_dir, "repo")
        os.makedirs(repo_path)
        
        # Don't add to tracked directories
        
        # Create a test file
        test_file = os.path.join(repo_path, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")
        
        assert os.path.exists(repo_path)
        
        # Cleanup (should fallback to removing just the repo directory)
        self.service.cleanup_repository(repo_path)
        
        # Verify repo directory is removed
        assert not os.path.exists(repo_path)
        # But parent temp directory might still exist
    
    def test_cleanup_repository_nonexistent(self):
        """Test cleanup of nonexistent repository (should not raise error)"""
        # This should not raise an exception
        self.service.cleanup_repository("/nonexistent/path")
    
    def test_cleanup_all_repositories(self):
        """Test cleanup of all tracked repositories"""
        # Create multiple temporary directories
        temp_dirs = []
        for i in range(3):
            temp_dir = tempfile.mkdtemp(prefix=f"codeshield_test_{i}_")
            temp_dirs.append(temp_dir)
            self.service._temp_dirs.add(temp_dir)
            
            # Create some content
            test_file = os.path.join(temp_dir, f"test{i}.txt")
            with open(test_file, "w") as f:
                f.write(f"test content {i}")
        
        # Verify all directories exist
        for temp_dir in temp_dirs:
            assert os.path.exists(temp_dir)
        
        # Cleanup all
        self.service.cleanup_all_repositories()
        
        # Verify all are cleaned up
        for temp_dir in temp_dirs:
            assert not os.path.exists(temp_dir)
        
        assert len(self.service._temp_dirs) == 0


class TestCompleteWorkflow:
    """Test cases for the complete validation and preparation workflow"""
    
    def setup_method(self):
        self.service = RepositoryService()
    
    def teardown_method(self):
        self.service.cleanup_all_repositories()
    
    @pytest.mark.asyncio
    async def test_validate_and_prepare_repository_success(self):
        """Test complete successful workflow"""
        url = "https://github.com/owner/repo"
        
        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": False,
            "size": 1024  # 1MB
        }
        
        with patch("httpx.AsyncClient") as mock_client, \
             patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone, \
             patch("os.path.exists") as mock_exists, \
             patch("os.path.isdir") as mock_isdir, \
             patch.object(self.service, "_get_directory_size_mb") as mock_size:
            
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_temp_dir = "/tmp/codeshield_test123"
            mock_clone_path = f"{mock_temp_dir}/repo"
            mock_mkdtemp.return_value = mock_temp_dir
            mock_clone.return_value = None
            mock_exists.return_value = True
            mock_isdir.return_value = True
            mock_size.return_value = 1.0  # 1MB
            
            repo_info, clone_path = await self.service.validate_and_prepare_repository(url)
            
            assert repo_info.url == "https://github.com/owner/repo"
            assert repo_info.owner == "owner"
            assert repo_info.name == "repo"
            assert repo_info.is_public is True
            assert repo_info.size_kb == 1024
            assert clone_path == mock_clone_path
    
    @pytest.mark.asyncio
    async def test_validate_and_prepare_repository_validation_error(self):
        """Test workflow with validation error"""
        url = "https://invalid-url"
        
        with pytest.raises(RepositoryValidationError):
            await self.service.validate_and_prepare_repository(url)
    
    @pytest.mark.asyncio
    async def test_validate_and_prepare_repository_accessibility_error(self):
        """Test workflow with accessibility error"""
        url = "https://github.com/owner/repo"
        
        # Mock GitHub API response for private repo
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": True,
            "size": 1024
        }
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with pytest.raises(RepositoryValidationError, match="is private"):
                await self.service.validate_and_prepare_repository(url)
    
    @pytest.mark.asyncio
    async def test_validate_and_prepare_repository_clone_error(self):
        """Test workflow with clone error"""
        url = "https://github.com/owner/repo"
        
        # Mock successful GitHub API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "private": False,
            "size": 1024
        }
        
        with patch("httpx.AsyncClient") as mock_client, \
             patch("tempfile.mkdtemp") as mock_mkdtemp, \
             patch.object(self.service, "_clone_repo_sync") as mock_clone:
            
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_mkdtemp.return_value = "/tmp/codeshield_test123"
            mock_clone.side_effect = GitCommandError("git clone", 128, "Repository not found")
            
            with pytest.raises(RepositoryCloneError, match="Git clone failed"):
                await self.service.validate_and_prepare_repository(url)