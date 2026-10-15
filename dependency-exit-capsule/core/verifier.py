"""Verification engine for baseline tests and isolated dependency replacement experiments."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TestDiscovery:
    """Discovered test suite and execution command."""

    __test__ = False

    framework: str  # pytest, unittest, npm, none
    command_args: List[str] = field(default_factory=list)
    config_file: Optional[str] = None
    test_files: List[str] = field(default_factory=list)
    available: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "command_args": self.command_args,
            "config_file": self.config_file,
            "test_files_count": len(self.test_files),
            "available": self.available,
            "description": self.description,
        }


@dataclass
class ExecutionResult:
    """Results from executing a test command."""

    command: List[str]
    exit_code: Optional[int]
    duration_ms: int
    status: str  # PASSED, FAILED, TIMED_OUT, SKIPPED, NOT_CONFIGURED, NOT_AUTHORIZED
    stdout_summary: str = ""
    stderr_summary: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "stdout_summary": self.stdout_summary,
            "stderr_summary": self.stderr_summary,
            "error_message": self.error_message,
        }


@dataclass
class ReplacementVerificationResult:
    """Outcome of attempting a safe, isolated replacement experiment."""

    target_package: str
    replacement_package: str
    experiment_attempted: bool
    status: str  # EXECUTION_VERIFIED, FAILED, NOT_TESTED, COMPATIBILITY_GAP
    baseline_status: str
    replacement_status: str
    compatibility_gaps: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_package": self.target_package,
            "replacement_package": self.replacement_package,
            "experiment_attempted": self.experiment_attempted,
            "status": self.status,
            "baseline_status": self.baseline_status,
            "replacement_status": self.replacement_status,
            "compatibility_gaps": self.compatibility_gaps,
            "notes": self.notes,
        }


class TestVerifier:
    """Safely discovers and runs baseline tests and isolated replacement checks."""

    __test__ = False

    def __init__(self, repo_path: Path, timeout: int = 30):
        self.repo_path = repo_path.resolve()
        self.timeout = timeout

    def discover_tests(self, ecosystems: List[str]) -> TestDiscovery:
        """Inspect repository to detect test framework, files, and commands."""
        # 1. Check Python test suites
        if "python" in ecosystems:
            # Check pytest indicators
            test_files = [
                str(p.relative_to(self.repo_path)).replace("\\", "/")
                for p in self.repo_path.rglob("test_*.py")
            ]
            test_files += [
                str(p.relative_to(self.repo_path)).replace("\\", "/")
                for p in self.repo_path.rglob("*_test.py")
            ]
            test_files = sorted(list(set(test_files)))

            has_tests_dir = (self.repo_path / "tests").is_dir()
            has_pytest_ini = (self.repo_path / "pytest.ini").is_file()

            if test_files or has_tests_dir:
                # Use sys.executable to ensure the exact matching Python environment is used
                # Pass -o pythonpath=. so packages inside the repo root are importable
                cmd = [sys.executable, "-m", "pytest", "-o", "pythonpath=."]
                if has_tests_dir:
                    cmd.append("tests")

                cfg = "pytest.ini" if has_pytest_ini else ("pyproject.toml" if (self.repo_path / "pyproject.toml").is_file() else None)
                return TestDiscovery(
                    framework="pytest",
                    command_args=cmd,
                    config_file=cfg,
                    test_files=test_files,
                    available=True,
                    description=f"pytest suite detected ({len(test_files)} test files found).",
                )

        # 2. Check JavaScript test suites
        if "javascript" in ecosystems:
            pkg_json = self.repo_path / "package.json"
            if pkg_json.is_file():
                try:
                    import json
                    data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                    scripts = data.get("scripts", {})
                    if "test" in scripts and "no test specified" not in scripts["test"].lower():
                        return TestDiscovery(
                            framework="npm",
                            command_args=["npm", "test"],
                            config_file="package.json",
                            test_files=[],
                            available=True,
                            description=f"npm test script found: '{scripts['test']}'",
                        )
                except Exception:
                    pass

        return TestDiscovery(
            framework="none",
            command_args=[],
            test_files=[],
            available=False,
            description="No supported automated test suite discovered in this repository.",
        )

    def run_baseline_tests(
        self,
        discovery: TestDiscovery,
        user_authorized: bool = False,
    ) -> ExecutionResult:
        """Run baseline test suite if authorized by the user."""
        if not discovery.available:
            return ExecutionResult(
                command=[],
                exit_code=None,
                duration_ms=0,
                status="NOT_CONFIGURED",
                error_message="No executable test suite discovered.",
            )

        if not user_authorized:
            return ExecutionResult(
                command=discovery.command_args,
                exit_code=None,
                duration_ms=0,
                status="NOT_AUTHORIZED",
                error_message="Execution withheld: user authorization is required to run repository code.",
            )

        # Execute discovered command safely without shell=True
        return self._execute_command(discovery.command_args, self.repo_path)

    def run_replacement_experiment(
        self,
        target_package: str,
        replacement_package: str,
        discovery: TestDiscovery,
        user_authorized: bool = False,
    ) -> ReplacementVerificationResult:
        """Execute isolated compatibility experiment in temporary copy of the repository."""
        if not user_authorized:
            return ReplacementVerificationResult(
                target_package=target_package,
                replacement_package=replacement_package,
                experiment_attempted=False,
                status="NOT_TESTED",
                baseline_status="NOT_AUTHORIZED",
                replacement_status="NOT_AUTHORIZED",
                notes="Execution withheld: explicit user authorization is required for migration verification.",
            )

        if not discovery.available:
            return ReplacementVerificationResult(
                target_package=target_package,
                replacement_package=replacement_package,
                experiment_attempted=False,
                status="NOT_TESTED",
                baseline_status="NOT_CONFIGURED",
                replacement_status="NOT_CONFIGURED",
                notes="Cannot verify replacement: no test suite exists in this repository to validate behavior.",
            )

        # Step 1: Run baseline on original repo
        baseline_res = self.run_baseline_tests(discovery, user_authorized=True)

        # Step 2: Create isolated temporary clone of the repository
        with tempfile.TemporaryDirectory(prefix="dep_verify_") as tmp_dir:
            temp_repo = Path(tmp_dir) / "repo"
            # Copy repository excluding git and caches
            shutil.copytree(
                self.repo_path,
                temp_repo,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "venv", ".venv"),
            )

            # Step 3: Perform small, well-defined patch on the temp copy
            patch_applied, patch_notes = self._apply_migration_patch(
                temp_repo, target_package, replacement_package
            )

            if not patch_applied:
                return ReplacementVerificationResult(
                    target_package=target_package,
                    replacement_package=replacement_package,
                    experiment_attempted=False,
                    status="NOT_TESTED",
                    baseline_status=baseline_res.status,
                    replacement_status="SKIPPED",
                    notes=f"No automated safe experiment defined for {target_package} -> {replacement_package}: {patch_notes}",
                )

            # Step 4: Run test suite in isolated directory
            replacement_res = self._execute_command(discovery.command_args, temp_repo)

            gaps = []
            if baseline_res.status == "PASSED" and replacement_res.status != "PASSED":
                status = "FAILED"
                gaps.append(f"Regression detected: baseline passed but replacement test failed with exit code {replacement_res.exit_code}.")
                if replacement_res.stderr_summary:
                    gaps.append(f"Error output: {replacement_res.stderr_summary[:300]}")
            elif baseline_res.status == "PASSED" and replacement_res.status == "PASSED":
                status = "EXECUTION_VERIFIED"
            else:
                status = "COMPATIBILITY_GAP"
                gaps.append(f"Baseline was '{baseline_res.status}', replacement resulted in '{replacement_res.status}'.")

            return ReplacementVerificationResult(
                target_package=target_package,
                replacement_package=replacement_package,
                experiment_attempted=True,
                status=status,
                baseline_status=baseline_res.status,
                replacement_status=replacement_res.status,
                compatibility_gaps=gaps,
                notes=f"{patch_notes}. Duration: {replacement_res.duration_ms}ms.",
            )

    def _apply_migration_patch(
        self, repo_dir: Path, target: str, replacement: str
    ) -> Tuple[bool, str]:
        """Apply safe in-place replacement patch to Python source files in the temp directory."""
        norm_target = target.lower().strip()
        norm_replacement = replacement.lower().strip()

        # Specific known drop-in migrations
        # 1. appdirs -> platformdirs
        if norm_target == "appdirs" and "platformdirs" in norm_replacement:
            count = 0
            for py_file in repo_dir.rglob("*.py"):
                try:
                    content = py_file.read_text(encoding="utf-8", errors="replace")
                    if "appdirs" in content:
                        new_content = content.replace("from appdirs import", "from platformdirs import")
                        new_content = new_content.replace("import appdirs", "import platformdirs as appdirs")
                        py_file.write_text(new_content, encoding="utf-8")
                        count += 1
                except Exception:
                    pass
            return (
                True,
                f"Patched appdirs imports to platformdirs across {count} file(s) in isolated temporary environment",
            )

        # 2. toml -> tomllib (Python 3.11+ built-in)
        if norm_target == "toml" and ("tomllib" in norm_replacement or "tomli" in norm_replacement):
            count = 0
            for py_file in repo_dir.rglob("*.py"):
                try:
                    content = py_file.read_text(encoding="utf-8", errors="replace")
                    if "import toml" in content:
                        # tomllib.loads or tomllib.load requires binary mode ('rb')
                        # In linkwatch/config.py: data = toml.load(path) -> with open(path, "rb") as f: data = tomllib.load(f)
                        new_content = content.replace(
                            "import toml",
                            "import tomllib\nclass _TomlCompat:\n    @staticmethod\n    def load(p):\n        with open(p, 'rb') as f:\n            return tomllib.load(f)\n    @staticmethod\n    def loads(s):\n        return tomllib.loads(s)\ntoml = _TomlCompat()",
                        )
                        py_file.write_text(new_content, encoding="utf-8")
                        count += 1
                except Exception:
                    pass
            return (
                True,
                f"Patched toml usage with standard library tomllib compatibility adapter across {count} file(s)",
            )

        return (
            False,
            f"Automated AST patch template not implemented for {target} -> {replacement}. Manual migration required.",
        )

    def _execute_command(self, cmd_args: List[str], cwd: Path) -> ExecutionResult:
        """Run a command with timeout and bounded output capture, avoiding shell=True."""
        start_time = time.monotonic()
        try:
            # Set PYTHONPATH to include cwd so local packages are importable
            env = os.environ.copy()
            existing_pythonpath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(cwd) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")

            proc = subprocess.run(
                cmd_args,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
            duration_ms = int((time.monotonic() - start_time) * 1000)
            status = "PASSED" if proc.returncode == 0 else "FAILED"

            return ExecutionResult(
                command=cmd_args,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                status=status,
                stdout_summary=proc.stdout[:2500].strip(),
                stderr_summary=proc.stderr[:2500].strip(),
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return ExecutionResult(
                command=cmd_args,
                exit_code=None,
                duration_ms=duration_ms,
                status="TIMED_OUT",
                error_message=f"Command timed out after {self.timeout} seconds.",
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return ExecutionResult(
                command=cmd_args,
                exit_code=None,
                duration_ms=duration_ms,
                status="FAILED",
                error_message=f"Execution error: {str(e)}",
            )
