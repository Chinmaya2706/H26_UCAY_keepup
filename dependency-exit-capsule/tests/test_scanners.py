"""Unit tests for repository inspection and Python/JavaScript dependency scanners."""

import tempfile
from pathlib import Path

import pytest

from core.verifier import TestVerifier
from scanners.javascript_scanner import JavaScriptScanner
from scanners.python_scanner import PythonScanner
from scanners.repository import RepositoryManager


def test_python_scanner_with_fixture():
    """Test Python manifest parsing, AST import extraction, and risk detection."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)

        # Create requirements.txt
        (repo / "requirements.txt").write_text(
            "requests==2.31.0\n"
            "pydantic==1.10.13\n"
            "six\n"
            "click>=7\n"
            "appdirs==1.4.4\n"
            "python-dateutil\n",
            encoding="utf-8",
        )

        # Create pyproject.toml with conflicting pydantic constraint
        (repo / "pyproject.toml").write_text(
            '[project]\n'
            'name = "sample-app"\n'
            'dependencies = [\n'
            '    "pydantic>=2.0.0",\n'
            '    "requests==2.31.0",\n'
            ']\n',
            encoding="utf-8",
        )

        # Create source files
        pkg_dir = repo / "sample_app"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")

        (pkg_dir / "main.py").write_text(
            "import requests\n"
            "from appdirs import user_cache_dir\n"
            "from dateutil import parser\n"
            "import undeclared_lib\n",
            encoding="utf-8",
        )

        # Run scanner
        scanner = PythonScanner(repo)
        deps, findings, usages = scanner.scan()

        dep_names = {d.name.lower() for d in deps}
        assert "requests" in dep_names
        assert "pydantic" in dep_names
        assert "six" in dep_names
        assert "click" in dep_names
        assert "appdirs" in dep_names
        assert "python-dateutil" in dep_names

        # Verify usage mapping
        appdirs_dep = next(d for d in deps if d.name.lower() == "appdirs")
        assert len(appdirs_dep.usage_locations) == 1
        assert appdirs_dep.usage_locations[0].line_number == 2
        assert "from appdirs import user_cache_dir" in appdirs_dep.usage_locations[0].snippet

        dateutil_dep = next(d for d in deps if d.name.lower() == "python-dateutil")
        assert len(dateutil_dep.usage_locations) == 1
        assert "from dateutil import parser" in dateutil_dep.usage_locations[0].snippet

        # Verify risk categories
        categories = {f.risk_category for f in findings}
        assert "MANIFEST_CONFLICT" in categories
        assert "UNPINNED_DEPENDENCY" in categories
        assert "LOOSE_CONSTRAINT" in categories
        assert "DEPRECATED_PACKAGE" in categories
        assert "UNUSED_DEPENDENCY" in categories
        assert "UNDECLARED_IMPORT" in categories

        # Verify specific findings
        conflict_finding = next(f for f in findings if f.risk_category == "MANIFEST_CONFLICT")
        assert conflict_finding.package_name.lower() == "pydantic"
        assert conflict_finding.severity == "HIGH"

        undeclared_finding = next(f for f in findings if f.risk_category == "UNDECLARED_IMPORT")
        assert undeclared_finding.package_name == "undeclared_lib"


def test_javascript_scanner_with_fixture():
    """Test JavaScript package.json parsing and import extraction."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)

        # Create package.json
        (repo / "package.json").write_text(
            """{
  "name": "sample-node-app",
  "dependencies": {
    "lodash": "*",
    "express": "^4.18.2",
    "request": "2.88.2",
    "@scope/my-pkg": "1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}""",
            encoding="utf-8",
        )

        src_dir = repo / "src"
        src_dir.mkdir()

        (src_dir / "index.js").write_text(
            "const express = require('express');\n"
            "import { helper } from '@scope/my-pkg';\n"
            "import axios from 'axios';\n",
            encoding="utf-8",
        )

        scanner = JavaScriptScanner(repo)
        deps, findings, usages = scanner.scan()

        dep_names = {d.name for d in deps}
        assert "lodash" in dep_names
        assert "express" in dep_names
        assert "request" in dep_names
        assert "@scope/my-pkg" in dep_names
        assert "jest" in dep_names

        # Verify usages
        express_dep = next(d for d in deps if d.name == "express")
        assert len(express_dep.usage_locations) == 1
        assert "require('express')" in express_dep.usage_locations[0].snippet

        scoped_dep = next(d for d in deps if d.name == "@scope/my-pkg")
        assert len(scoped_dep.usage_locations) == 1

        # Verify risks
        categories = {f.risk_category for f in findings}
        assert "UNPINNED_DEPENDENCY" in categories
        assert "DEPRECATED_PACKAGE" in categories
        assert "UNUSED_DEPENDENCY" in categories
        assert "UNDECLARED_IMPORT" in categories


def test_empty_repository():
    """Test handling of an empty repository."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)
        mgr = RepositoryManager(str(repo))
        info = mgr.prepare()
        assert info.is_empty is True
        assert len(info.detected_ecosystems) == 0


def test_unsupported_repository():
    """Test repository with no recognized manifest files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)
        (repo / "notes.txt").write_text("Hello world", encoding="utf-8")
        mgr = RepositoryManager(str(repo))
        info = mgr.prepare()
        assert info.is_empty is False
        assert len(info.detected_ecosystems) == 0
        assert info.warning is not None


def test_no_tests_available():
    """Test discovery when repository has no test files or configuration."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)
        (repo / "requirements.txt").write_text("requests==2.31.0", encoding="utf-8")
        (repo / "main.py").write_text("import requests", encoding="utf-8")

        verifier = TestVerifier(repo)
        discovery = verifier.discover_tests(["python"])
        assert discovery.available is False
        assert discovery.framework == "none"

        result = verifier.run_baseline_tests(discovery, user_authorized=True)
        assert result.status == "NOT_CONFIGURED"
