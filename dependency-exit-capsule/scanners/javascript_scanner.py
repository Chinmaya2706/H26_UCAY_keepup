"""JavaScript and TypeScript dependency scanner, import inspector, and risk analyzer."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .models import DependencyItem, RiskFinding, UsageLocation

# Node.js built-in modules to ignore in source imports
NODE_BUILTINS: Set[str] = {
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "test",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
}

# Known npm deprecations / migration targets
KNOWN_JS_MAINTENANCE_ISSUES: Dict[str, Dict[str, str]] = {
    "request": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "HIGH",
        "evidence": "The 'request' package was fully deprecated in 2020. Modern alternatives include undici, axios, or native fetch.",
        "source": "npm advisory / request deprecation notice",
    },
    "moment": {
        "category": "DEPRECATED_PACKAGE",
        "severity": "MEDIUM",
        "evidence": "Moment.js is in maintenance-only mode and discourages new use. Recommended alternatives: dayjs, luxon, or date-fns.",
        "source": "Moment.js project status documentation",
    },
    "core-js": {
        "category": "MAINTENANCE_RISK",
        "severity": "LOW",
        "evidence": "Check if polyfills are needed for current target Node/browser matrix.",
        "source": "Ecosystem Guidelines",
    },
}

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
IGNORED_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
}

# Regex for ES import/export statements and CommonJS require()
# Matches:
# import ... from 'package' or "package"
# import 'package'
# import('package')
# require('package')
# export ... from 'package'
IMPORT_REGEXES = [
    re.compile(r"""(?:import|export)\s+(?:.*?from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
]


class JavaScriptScanner:
    """Scans JavaScript and TypeScript manifests, imports, and risks."""

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()

    def scan(self) -> Tuple[List[DependencyItem], List[RiskFinding], Dict[str, List[UsageLocation]]]:
        """Execute JS/TS scan: parse package.json, inspect source imports, analyze risks."""
        dependencies = self.parse_package_json()
        import_usages = self.inspect_source_code()

        self.map_usages_to_dependencies(dependencies, import_usages)
        findings = self.analyze_risks(dependencies, import_usages)

        return dependencies, findings, import_usages

    def parse_package_json(self) -> List[DependencyItem]:
        """Parse package.json and extract all dependency sections."""
        pkg_json = self.repo_path / "package.json"
        if not pkg_json.is_file():
            return []

        rel_path = str(pkg_json.relative_to(self.repo_path)).replace("\\", "/")
        try:
            content = pkg_json.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception:
            return []

        sections = [
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("optionalDependencies", "optional"),
            ("peerDependencies", "peer"),
        ]

        dependencies: List[DependencyItem] = []
        seen: Set[str] = set()

        for section_key, dep_type in sections:
            sec_dict = data.get(section_key, {})
            if isinstance(sec_dict, dict):
                for name, spec in sec_dict.items():
                    if name not in seen:
                        seen.add(name)
                        dependencies.append(
                            DependencyItem(
                                name=name,
                                ecosystem="javascript",
                                version_spec=str(spec),
                                manifest_file=rel_path,
                                dep_type=dep_type,
                            )
                        )

        return dependencies

    def inspect_source_code(self) -> Dict[str, List[UsageLocation]]:
        """Walk JS/TS source files and extract module import statements."""
        usages: Dict[str, List[UsageLocation]] = {}

        for file_path in self.repo_path.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in JS_EXTENSIONS:
                continue

            rel_parts = file_path.relative_to(self.repo_path).parts
            if any(part in IGNORED_DIRS or part.startswith(".") for part in rel_parts[:-1]):
                continue

            rel_file_str = str(file_path.relative_to(self.repo_path)).replace("\\", "/")
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except Exception:
                continue

            for line_no, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if not line or line.startswith("//") or line.startswith("/*"):
                    continue

                for pattern in IMPORT_REGEXES:
                    for match in pattern.finditer(line):
                        specifier = match.group(1).strip()
                        package_name = self._extract_package_name(specifier)
                        if not package_name:
                            continue

                        # Filter builtins
                        clean_pkg = package_name.removeprefix("node:")
                        if clean_pkg in NODE_BUILTINS:
                            continue

                        loc = UsageLocation(
                            file_path=rel_file_str,
                            line_number=line_no,
                            snippet=line,
                            import_name=package_name,
                        )
                        usages.setdefault(package_name, []).append(loc)

        return usages

    def _extract_package_name(self, specifier: str) -> Optional[str]:
        """Extract npm package name from an import path (handling relative & scoped)."""
        if specifier.startswith(".") or specifier.startswith("/"):
            return None  # Relative internal import

        parts = specifier.split("/")
        if specifier.startswith("@"):
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
            return specifier
        return parts[0]

    def map_usages_to_dependencies(
        self,
        dependencies: List[DependencyItem],
        import_usages: Dict[str, List[UsageLocation]],
    ):
        """Map extracted JS/TS imports to declared DependencyItem objects."""
        for dep in dependencies:
            dep_name = dep.name
            locs: List[UsageLocation] = []

            # Exact match or case-insensitive match
            for imp_name, usage_list in import_usages.items():
                if imp_name == dep_name or imp_name.lower() == dep_name.lower():
                    locs.extend(usage_list)

            # Deduplicate by file and line
            unique: Dict[Tuple[str, int], UsageLocation] = {}
            for loc in locs:
                unique[(loc.file_path, loc.line_number)] = loc

            dep.usage_locations = sorted(
                list(unique.values()), key=lambda u: (u.file_path, u.line_number)
            )

    def analyze_risks(
        self,
        dependencies: List[DependencyItem],
        import_usages: Dict[str, List[UsageLocation]],
    ) -> List[RiskFinding]:
        """Identify risk findings for JS/TS dependencies."""
        findings: List[RiskFinding] = []
        declared_names: Set[str] = set()

        for dep in dependencies:
            declared_names.add(dep.name.lower())
            spec = dep.version_spec.strip()

            # Unpinned / wildcard
            if spec in ("*", "latest") or spec == "":
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=spec or "unpinned",
                        ecosystem="javascript",
                        risk_category="UNPINNED_DEPENDENCY",
                        severity="MEDIUM",
                        evidence=f"Dependency version constraint '{spec}' resolves to latest, making builds non-reproducible.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

            # Loose version range (e.g. ^0.x is loose for zero-major, or >= without upper bound)
            elif (spec.startswith(">=") or spec.startswith(">")) and "<" not in spec:
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=spec,
                        ecosystem="javascript",
                        risk_category="LOOSE_CONSTRAINT",
                        severity="LOW",
                        evidence=f"Loose constraint '{spec}' allows unbounded major updates.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

            # Deprecated npm packages
            if dep.name.lower() in KNOWN_JS_MAINTENANCE_ISSUES:
                issue = KNOWN_JS_MAINTENANCE_ISSUES[dep.name.lower()]
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="javascript",
                        risk_category=issue["category"],
                        severity=issue["severity"],
                        evidence=issue["evidence"],
                        source=issue["source"],
                        status="EXTERNALLY_VERIFIED",
                    )
                )

            # Unused dependencies (runtime deps with 0 usage)
            if dep.dep_type == "runtime" and not dep.usage_locations:
                findings.append(
                    RiskFinding(
                        package_name=dep.name,
                        declared_version=dep.version_spec,
                        ecosystem="javascript",
                        risk_category="UNUSED_DEPENDENCY",
                        severity="LOW",
                        evidence="Package is listed in dependencies but has no matching import/require calls in source code.",
                        source=dep.manifest_file,
                        status="OBSERVED",
                    )
                )

        # Undeclared imports in source files
        for imp_name, locs in import_usages.items():
            if imp_name.lower() not in declared_names and not imp_name.startswith("@types/"):
                first_loc = locs[0]
                findings.append(
                    RiskFinding(
                        package_name=imp_name,
                        declared_version="undeclared",
                        ecosystem="javascript",
                        risk_category="UNDECLARED_IMPORT",
                        severity="MEDIUM",
                        evidence=f"Imported at {first_loc.file_path}:L{first_loc.line_number} ('{first_loc.snippet}') but not listed in package.json.",
                        source=f"{first_loc.file_path}:L{first_loc.line_number}",
                        status="OBSERVED",
                        details={"usage_count": len(locs)},
                    )
                )

        return findings
