"""Python dependency scanner, AST source code inspector, and risk analyzer."""

import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Python 3.11+ standard library tomllib
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

from .models import DependencyItem, RiskFinding, UsageLocation

# Well-known import name to PyPI package name mappings
KNOWN_IMPORT_TO_PACKAGE: Dict[str, str] = {
    "dateutil": "python-dateutil",
    "pkg_resources": "setuptools",
    "setuptools": "setuptools",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "serial": "pyserial",
    "magic": "python-magic",
    "jose": "python-jose",
    "git": "GitPython",
    "dns": "dnspython",
    "websocket": "websocket-client",
    "google.genai": "google-genai",
    "google.protobuf": "protobuf",
    "requests": "requests",
    "jinja2": "Jinja2",
    "pydantic": "pydantic",
    "click": "click",
    "rich": "rich",
    "toml": "toml",
    "appdirs": "appdirs",
    "chardet": "chardet",
    "idna": "idna",
    "certifi": "certifi",
    "six": "six",
}

# Reverse mapping for package name to expected import name
KNOWN_PACKAGE_TO_IMPORTS: Dict[str, List[str]] = {
    "python-dateutil": ["dateutil"],
    "setuptools": ["setuptools", "pkg_resources"],
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "opencv-python": ["cv2"],
    "scikit-learn": ["sklearn"],
    "python-dotenv": ["dotenv"],
    "pyjwt": ["jwt"],
    "pyserial": ["serial"],
    "gitpython": ["git"],
    "dnspython": ["dns"],
    "websocket-client": ["websocket"],
    "jinja2": ["jinja2"],
}

# Documented legacy or unmaintained packages with factual evidence
KNOWN_MAINTENANCE_ISSUES: Dict[str, Dict[str, str]] = {
    "appdirs": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "HIGH",
        "evidence": "appdirs was abandoned by upstream maintainers in 2020. The official active fork is platformdirs.",
        "source": "Ecosystem Advisory / Community Migration to platformdirs",
    },
    "toml": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "MEDIUM",
        "evidence": "toml has been inactive since 2020. Python 3.11+ includes built-in tomllib (PEP 680), and tomli/rtoml are standard modern alternatives.",
        "source": "PEP 680 / Python 3.11 Standard Library Release",
    },
    "pkg_resources": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "HIGH",
        "evidence": "pkg_resources is officially deprecated by setuptools due to slow startup and legacy design; importlib.resources is standard.",
        "source": "setuptools upstream deprecation notice (v67+)",
    },
    "six": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "LOW",
        "evidence": "six is a Python 2/3 compatibility library. For Python 3.10+ codebases, Python 2 compatibility shims are obsolete.",
        "source": "Python 2 Sunset / Ecosystem Standards",
    },
}

IGNORED_DIRS = {
    ".git",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "build",
    "dist",
    "*.egg-info",
}


def normalize_name(name: str) -> str:
    """Normalize package name according to PEP 503 (lowercase, dashes replaced)."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


class PythonScanner:
    """Scans Python repository manifests, tracks AST imports, and identifies risks."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()
        self.stdlib_modules = set(sys.stdlib_module_names)
        self.local_modules = self._discover_local_modules()

    def _discover_local_modules(self) -> Set[str]:
        """Find top-level Python modules and packages defined inside the repository."""
        local = set()
        for item in self.repo_path.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                local.add(item.name.lower())
            elif item.is_file() and item.suffix == ".py":
                local.add(item.stem.lower())

        # Also check src/ directory if present
        src_dir = self.repo_path / "src"
        if src_dir.is_dir():
            for item in src_dir.iterdir():
                if item.is_dir() and (item / "__init__.py").exists():
                    local.add(item.name.lower())
                elif item.is_file() and item.suffix == ".py":
                    local.add(item.stem.lower())
        return local

    def scan(self) -> Tuple[List[DependencyItem], List[RiskFinding], Dict[str, List[UsageLocation]]]:
        """Execute full scan: parse manifests, map AST usage, and detect risks."""
        dependencies, manifest_declarations = self.parse_all_manifests()
        import_usages = self.inspect_source_code()

        # Map usages to dependencies
        self.map_usages_to_dependencies(dependencies, import_usages)

        # Detect risks
        findings = self.analyze_risks(dependencies, manifest_declarations, import_usages)

        return dependencies, findings, import_usages

    def parse_all_manifests(self) -> Tuple[List[DependencyItem], Dict[str, List[Tuple[str, str, str]]]]:
        """Parse all Python manifests and return inventory and raw declaration map."""
        dependencies_dict: Dict[str, DependencyItem] = {}
        # Map: normalized_name -> list of (raw_name, version_spec, manifest_file)
        manifest_declarations: Dict[str, List[Tuple[str, str, str]]] = {}

        # 1. Parse requirements*.txt
        for req_file in self.repo_path.glob("requirements*.txt"):
            self._parse_requirements_file(req_file, dependencies_dict, manifest_declarations)

        # 2. Parse requirements/*.txt
        for req_file in self.repo_path.glob("requirements/*.txt"):
            self._parse_requirements_file(req_file, dependencies_dict, manifest_declarations)

        # 3. Parse pyproject.toml
        pyproject = self.repo_path / "pyproject.toml"
        if pyproject.is_file() and tomllib:
            self._parse_pyproject_toml(pyproject, dependencies_dict, manifest_declarations)

        # 4. Parse Pipfile if present
        pipfile = self.repo_path / "Pipfile"
        if pipfile.is_file():
            self._parse_pipfile(pipfile, dependencies_dict, manifest_declarations)

        return list(dependencies_dict.values()), manifest_declarations

    def _parse_requirements_file(
        self,
        file_path: Path,
        dep_dict: Dict[str, DependencyItem],
        decl_map: Dict[str, List[Tuple[str, str, str]]],
    ):
        rel_path = str(file_path.relative_to(self.repo_path)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        is_dev = "dev" in rel_path.lower() or "test" in rel_path.lower()
        dep_type = "dev" if is_dev else "runtime"

        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip inline comments
            line = re.split(r"\s+#", line)[0].strip()

            # Ignore flags like -r, -i, -e, --extra-index-url
            if line.startswith(("-", "--")):
                continue

            # Strip environment markers (e.g. ; python_version < '3.8')
            spec_part = line.split(";")[0].strip()
            if not spec_part:
                continue

            # Match package name and version specification
            match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", spec_part)
            if not match:
                continue

            pkg_name = match.group(1).strip()
            version_constraint = match.group(2).strip() or "unpinned"
            norm = normalize_name(pkg_name)

            decl_entry = (pkg_name, version_constraint, f"{rel_path}:L{line_no}")
            decl_map.setdefault(norm, []).append(decl_entry)

            if norm not in dep_dict:
                dep_dict[norm] = DependencyItem(
                    name=pkg_name,
                    ecosystem="python",
                    version_spec=version_constraint,
                    manifest_file=rel_path,
                    dep_type=dep_type,
                )

    def _parse_pyproject_toml(
        self,
        file_path: Path,
        dep_dict: Dict[str, DependencyItem],
        decl_map: Dict[str, List[Tuple[str, str, str]]],
    ):
        rel_path = str(file_path.relative_to(self.repo_path)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            data = tomllib.loads(content)
        except Exception:
            return

        # PEP 621 project.dependencies
        project = data.get("project", {})
        dependencies = project.get("dependencies", [])
        for item in dependencies:
            self._parse_pep508_dep(item, rel_path, "runtime", dep_dict, decl_map)

        # PEP 621 project.optional-dependencies
        opt_deps = project.get("optional-dependencies", {})
        for group, items in opt_deps.items():
            dep_type = "dev" if group.lower() in ("dev", "test", "lint") else "optional"
            for item in items:
                self._parse_pep508_dep(item, rel_path, dep_type, dep_dict, decl_map)

        # Poetry tool.poetry.dependencies
        poetry = data.get("tool", {}).get("poetry", {})
        poetry_deps = poetry.get("dependencies", {})
        for pkg, spec in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            spec_str = str(spec) if isinstance(spec, (str, int, float)) else "unpinned"
            norm = normalize_name(pkg)
            decl_entry = (pkg, spec_str, rel_path)
            decl_map.setdefault(norm, []).append(decl_entry)
            if norm not in dep_dict:
                dep_dict[norm] = DependencyItem(
                    name=pkg,
                    ecosystem="python",
                    version_spec=spec_str,
                    manifest_file=rel_path,
                    dep_type="runtime",
                )

    def _parse_pep508_dep(
        self,
        dep_str: str,
        manifest_file: str,
        dep_type: str,
        dep_dict: Dict[str, DependencyItem],
        decl_map: Dict[str, List[Tuple[str, str, str]]],
    ):
        clean = dep_str.split(";")[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", clean)
        if not match:
            return
        pkg_name = match.group(1).strip()
        version_spec = match.group(2).strip() or "unpinned"
        norm = normalize_name(pkg_name)

        decl_entry = (pkg_name, version_spec, manifest_file)
        decl_map.setdefault(norm, []).append(decl_entry)

        if norm not in dep_dict:
            dep_dict[norm] = DependencyItem(
                name=pkg_name,
                ecosystem="python",
                version_spec=version_spec,
                manifest_file=manifest_file,
                dep_type=dep_type,
            )

    def _parse_pipfile(
        self,
        file_path: Path,
        dep_dict: Dict[str, DependencyItem],
        decl_map: Dict[str, List[Tuple[str, str, str]]],
    ):
        rel_path = str(file_path.relative_to(self.repo_path)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        current_section = None
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip().lower()
                continue

            if current_section in ("packages", "dev-packages") and "=" in line:
                parts = line.split("=", 1)
                pkg = parts[0].strip().strip('"').strip("'")
                val = parts[1].strip().strip('"').strip("'")
                norm = normalize_name(pkg)
                dep_type = "dev" if current_section == "dev-packages" else "runtime"
                decl_entry = (pkg, val, f"{rel_path}:L{line_no}")
                decl_map.setdefault(norm, []).append(decl_entry)
                if norm not in dep_dict:
                    dep_dict[norm] = DependencyItem(
                        name=pkg,
                        ecosystem="python",
                        version_spec=val,
                        manifest_file=rel_path,
                        dep_type=dep_type,
                    )

    def inspect_source_code(self) -> Dict[str, List[UsageLocation]]:
        """Walk repository and inspect all Python files with AST."""
        usages: Dict[str, List[UsageLocation]] = {}

        for py_path in self.repo_path.rglob("*.py"):
            # Check excluded directories
            rel_parts = py_path.relative_to(self.repo_path).parts
            if any(part in IGNORED_DIRS or part.startswith(".") for part in rel_parts[:-1]):
                continue

            rel_file_str = str(py_path.relative_to(self.repo_path)).replace("\\", "/")
            try:
                code = py_path.read_text(encoding="utf-8", errors="replace")
                lines = code.splitlines()
                tree = ast.parse(code, filename=str(py_path))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_module = alias.name.split(".")[0]
                        lineno = node.lineno
                        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"import {alias.name}"
                        self._record_import_usage(top_module, rel_file_str, lineno, snippet, usages)

                elif isinstance(node, ast.ImportFrom):
                    # If level > 0, it's a relative import (internal to the package)
                    if node.level and node.level > 0:
                        continue
                    if node.module:
                        top_module = node.module.split(".")[0]
                        lineno = node.lineno
                        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"from {node.module} import ..."
                        self._record_import_usage(top_module, rel_file_str, lineno, snippet, usages)

        return usages

    def _record_import_usage(
        self,
        module_name: str,
        file_path: str,
        line_no: int,
        snippet: str,
        usages: Dict[str, List[UsageLocation]],
    ):
        """Record usage if not standard library or local project module."""
        mod_lower = module_name.lower()
        if mod_lower in self.stdlib_modules:
            return
        if mod_lower in self.local_modules:
            return

        loc = UsageLocation(
            file_path=file_path,
            line_number=line_no,
            snippet=snippet,
            import_name=module_name,
        )
        usages.setdefault(mod_lower, []).append(loc)

    def map_usages_to_dependencies(
        self,
        dependencies: List[DependencyItem],
        import_usages: Dict[str, List[UsageLocation]],
    ):
        """Map AST discovered import usages to declared DependencyItem objects."""
        for dep in dependencies:
            norm = normalize_name(dep.name)
            candidate_imports = set()

            # Default candidates
            candidate_imports.add(norm)
            candidate_imports.add(norm.replace("-", "_"))
            candidate_imports.add(dep.name.lower())

            # Known reverse mappings
            if norm in KNOWN_PACKAGE_TO_IMPORTS:
                for imp in KNOWN_PACKAGE_TO_IMPORTS[norm]:
                    candidate_imports.add(imp.lower())

            matched_locs: List[UsageLocation] = []
            for candidate in candidate_imports:
                if candidate in import_usages:
                    matched_locs.extend(import_usages[candidate])

            # Deduplicate locations
            unique_locs: Dict[Tuple[str, int], UsageLocation] = {}
            for loc in matched_locs:
                key = (loc.file_path, loc.line_number)
                if key not in unique_locs:
                    unique_locs[key] = loc

            dep.usage_locations = sorted(
                list(unique_locs.values()), key=lambda u: (u.file_path, u.line_number)
            )

    def analyze_risks(
        self,
        dependencies: List[DependencyItem],
        manifest_declarations: Dict[str, List[Tuple[str, str, str]]],
        import_usages: Dict[str, List[UsageLocation]],
    ) -> List[RiskFinding]:
        """Generate risk findings with supporting evidence and explicit statuses."""
        findings: List[RiskFinding] = []

        # 1. Manifest Conflicts (e.g. pydantic==1.10.13 vs pydantic>=2)
        for norm_name, decls in manifest_declarations.items():
            if len(decls) > 1:
                # Compare unique version specs across manifests
                specs = set((spec, src.split(":")[0]) for _, spec, src in decls)
                unique_specs = set(spec for spec, _ in specs)
                if len(unique_specs) > 1:
                    src_summary = ", ".join(f"{src}: '{spec}'" for spec, src in specs)
                    findings.append(
                        RiskFinding(
                            package_name=decls[0][0],
                            declared_version=" / ".join(unique_specs),
                            ecosystem="python",
                            risk_category="MANIFEST_CONFLICT",
                            severity="HIGH",
                            evidence=f"Conflicting version constraints declared across manifests: {src_summary}.",
                            source="; ".join(src for _, _, src in decls),
                            status="OBSERVED",
                            details={"declarations": [{"package": p, "spec": s, "source": src} for p, s, src in decls]},
                        )
                    )

        # 2. Per-dependency inspection
        declared_normalized = set()
        for dep in dependencies:
            norm = normalize_name(dep.name)
            declared_normalized.add(norm)

            # Unpinned dependency check
            if dep.version_spec == "unpinned":
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="python",
                        risk_category="UNPINNED_DEPENDENCY",
                        severity="LOW",
                        evidence="Package declared without pinned version or upper boundary; builds are non-reproducible and vulnerable to breaking upstream releases.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

            # Loose version constraint (e.g. >= without upper bound)
            elif (
                (dep.version_spec.startswith(">=") or dep.version_spec.startswith(">"))
                and "<" not in dep.version_spec
                and "," not in dep.version_spec
            ):
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="python",
                        risk_category="LOOSE_CONSTRAINT",
                        severity="LOW",
                        evidence=f"Loose constraint '{dep.version_spec}' allows unbounded major updates that may introduce breaking API changes.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

            # Deprecated / unmaintained package check
            if norm in KNOWN_MAINTENANCE_ISSUES:
                issue = KNOWN_MAINTENANCE_ISSUES[norm]
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="python",
                        risk_category=issue["category"],
                        severity=issue["severity"],
                        evidence=issue["evidence"],
                        source=issue["source"],
                        status="EXTERNALLY_VERIFIED",
                    )
                )

            # Unused dependency check (runtime dependencies with 0 usages in repo)
            if dep.dep_type == "runtime" and not dep.usage_locations:
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="python",
                        risk_category="UNUSED_DEPENDENCY",
                        severity="LOW",
                        evidence="Package is declared as a runtime dependency in manifests but has no corresponding import statements in repository source files.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

        # 3. Undeclared Imports (imported in source code but not found in any manifest)
        for import_name, locs in import_usages.items():
            mapped_pkg = KNOWN_IMPORT_TO_PACKAGE.get(import_name, import_name)
            norm_pkg = normalize_name(mapped_pkg)

            if norm_pkg not in declared_normalized and import_name not in declared_normalized:
                first_loc = locs[0]
                findings.append(
                    RiskFinding(
                        package_name=mapped_pkg,
                        declared_version="undeclared",
                        ecosystem="python",
                        risk_category="UNDECLARED_IMPORT",
                        severity="MEDIUM",
                        evidence=f"Module '{import_name}' is imported at {first_loc.file_path}:L{first_loc.line_number} ('{first_loc.snippet}') but is not explicitly declared in any manifest.",
                        source=f"{first_loc.file_path}:L{first_loc.line_number}",
                        status="OBSERVED",
                        details={"usage_count": len(locs)},
                    )
                )

        return findings
