"""Repository inspection, cloning, and ecosystem detection module."""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set


GITHUB_URL_PATTERN = re.compile(
    r"^(https?://)?(www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$"
)

PYTHON_MANIFEST_PATTERNS = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/*.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "Pipfile.lock",
]

JS_MANIFEST_PATTERNS = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
]


@dataclass
class RepositoryInfo:
    """Metadata and detected ecosystems for an inspected repository."""

    source: str
    is_remote: bool
    local_path: Path
    detected_ecosystems: List[str] = field(default_factory=list)
    manifest_files: List[str] = field(default_factory=list)
    commit_hash: Optional[str] = None
    is_empty: bool = False
    warning: Optional[str] = None


class RepositoryError(Exception):
    """Raised when repository cloning, validation, or inspection fails."""
    pass


class RepositoryManager:
    """Manages cloning of remote repositories or validation of local directories."""

    def __init__(self, source: str, clone_timeout: int = 60):
        self.source = source.strip()
        self.clone_timeout = clone_timeout
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.repo_dir: Optional[Path] = None
        self.is_remote = False

    def __enter__(self) -> RepositoryInfo:
        return self.prepare()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Clean up temporary directory if created."""
        if self.temp_dir:
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass
            self.temp_dir = None
            self.repo_dir = None

    def prepare(self) -> RepositoryInfo:
        """Validate input, clone if remote or verify if local, and inspect ecosystems."""
        if not self.source:
            raise RepositoryError("Repository source cannot be empty.")

        if self._is_github_url(self.source):
            self.is_remote = True
            repo_path = self._clone_repo(self.source)
        else:
            self.is_remote = False
            repo_path = self._verify_local_path(self.source)

        self.repo_dir = repo_path
        commit_hash = self._get_commit_hash(repo_path)
        is_empty = self._is_repo_empty(repo_path)

        if is_empty:
            return RepositoryInfo(
                source=self.source,
                is_remote=self.is_remote,
                local_path=repo_path,
                detected_ecosystems=[],
                manifest_files=[],
                commit_hash=commit_hash,
                is_empty=True,
                warning="The repository appears to be empty.",
            )

        ecosystems, manifests = self.detect_ecosystems(repo_path)
        warning = None
        if not ecosystems:
            warning = "No recognized Python or JavaScript manifests found. Repository may use an unsupported ecosystem."

        return RepositoryInfo(
            source=self.source,
            is_remote=self.is_remote,
            local_path=repo_path,
            detected_ecosystems=ecosystems,
            manifest_files=manifests,
            commit_hash=commit_hash,
            is_empty=False,
            warning=warning,
        )

    def _is_github_url(self, source: str) -> bool:
        """Check if source is a GitHub URL."""
        if source.startswith(("http://", "https://", "git@")):
            return bool(GITHUB_URL_PATTERN.match(source.strip()))
        return False

    def _clone_repo(self, url: str) -> Path:
        """Clone a remote GitHub repository into a temporary directory."""
        clean_url = url.strip()
        if not clean_url.endswith(".git") and not clean_url.startswith("git@"):
            clean_url = clean_url.rstrip("/") + ".git"

        # Check git availability
        try:
            subprocess.run(
                ["git", "--version"],
                capture_output=True,
                check=True,
                text=True,
            )
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise RepositoryError(
                "Git CLI is required to clone remote repositories, but was not found."
            ) from e

        self.temp_dir = tempfile.TemporaryDirectory(prefix="dep_capsule_")
        target_path = Path(self.temp_dir.name)

        try:
            cmd = ["git", "clone", "--depth", "1", clean_url, str(target_path)]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout,
            )
            if proc.returncode != 0:
                err_msg = proc.stderr.strip() or proc.stdout.strip() or "Unknown clone error"
                raise RepositoryError(f"Failed to clone repository '{url}': {err_msg}")
        except subprocess.TimeoutExpired as e:
            raise RepositoryError(
                f"Repository cloning timed out after {self.clone_timeout} seconds."
            ) from e

        return target_path

    def _verify_local_path(self, path_str: str) -> Path:
        """Verify that local path exists, is a directory, and is readable."""
        path = Path(path_str).resolve()
        if not path.exists():
            raise RepositoryError(f"Local path does not exist: {path_str}")
        if not path.is_dir():
            raise RepositoryError(f"Local path is not a directory: {path_str}")
        return path

    def _is_repo_empty(self, path: Path) -> bool:
        """Check if directory contains any files other than .git."""
        try:
            for item in path.iterdir():
                if item.name != ".git":
                    return False
            return True
        except Exception:
            return True

    def _get_commit_hash(self, path: Path) -> Optional[str]:
        """Attempt to extract HEAD commit hash if git repository."""
        git_dir = path / ".git"
        if not git_dir.exists():
            return None
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(path),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
        except Exception:
            pass
        return None

    @staticmethod
    def detect_ecosystems(repo_path: Path) -> tuple[List[str], List[str]]:
        """Detect supported ecosystems (Python, JavaScript) by inspecting manifest files."""
        detected: Set[str] = set()
        manifests: List[str] = []

        # Check Python manifests
        for item in repo_path.glob("requirements*.txt"):
            rel = str(item.relative_to(repo_path)).replace("\\", "/")
            manifests.append(rel)
            detected.add("python")

        for req_item in repo_path.glob("requirements/*.txt"):
            rel = str(req_item.relative_to(repo_path)).replace("\\", "/")
            manifests.append(rel)
            detected.add("python")

        for py_file in ["pyproject.toml", "Pipfile", "setup.py", "setup.cfg", "poetry.lock", "Pipfile.lock"]:
            target = repo_path / py_file
            if target.is_file():
                manifests.append(py_file)
                detected.add("python")

        # Check JS/TS manifests
        for js_file in JS_MANIFEST_PATTERNS:
            target = repo_path / js_file
            if target.is_file():
                manifests.append(js_file)
                detected.add("javascript")

        # Sort for deterministic output
        sorted_manifests = sorted(list(set(manifests)))
        sorted_ecosystems = sorted(list(detected))
        return sorted_ecosystems, sorted_manifests
