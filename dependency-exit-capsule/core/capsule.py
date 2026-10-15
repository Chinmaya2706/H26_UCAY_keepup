"""Dependency Exit Capsule exporter in Markdown and machine-readable JSON."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanners.models import DependencyItem, RiskFinding
from scanners.repository import RepositoryInfo
from .gemma import GemmaAnalysisResult
from .verifier import ExecutionResult, ReplacementVerificationResult, TestDiscovery


class CapsuleExporter:
    """Exports standardized Dependency Exit Capsules in Markdown and JSON."""

    def __init__(
        self,
        repo_info: RepositoryInfo,
        dependencies: List[DependencyItem],
        findings: List[RiskFinding],
        gemma_result: Optional[GemmaAnalysisResult] = None,
        test_discovery: Optional[TestDiscovery] = None,
        baseline_result: Optional[ExecutionResult] = None,
        replacement_results: Optional[List[ReplacementVerificationResult]] = None,
    ):
        self.repo_info = repo_info
        self.dependencies = dependencies
        self.findings = findings
        self.gemma_result = gemma_result
        self.test_discovery = test_discovery
        self.baseline_result = baseline_result
        self.replacement_results = replacement_results or []
        self.timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def to_dict(self) -> Dict[str, Any]:
        """Generate structured machine-readable dictionary representation."""
        # Categorize findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        return {
            "capsule_version": "1.0.0",
            "metadata": {
                "repository_source": self.repo_info.source,
                "is_remote": self.repo_info.is_remote,
                "commit_hash": self.repo_info.commit_hash or "UNKNOWN",
                "analysis_timestamp": self.timestamp,
                "detected_ecosystems": self.repo_info.detected_ecosystems,
                "manifest_files": self.repo_info.manifest_files,
                "total_dependencies": len(self.dependencies),
                "total_findings": len(self.findings),
                "severity_summary": severity_counts,
            },
            "status_taxonomy": {
                "OBSERVED": "Directly extracted from repository manifests or AST code analysis",
                "EXTERNALLY_VERIFIED": "Corroborated by official package registries or ecosystem deprecation advisories",
                "AI_RECOMMENDATION": "Migration plan proposed by Gemma 4",
                "EXECUTION_VERIFIED": "Real execution test passed in isolated environment",
                "FAILED": "Real execution test failed during verification",
                "NOT_TESTED": "Verification was skipped or withheld",
                "UNKNOWN": "Status could not be definitively determined",
            },
            "dependency_inventory": [d.to_dict() for d in self.dependencies],
            "risk_findings": [f.to_dict() for f in self.findings],
            "gemma_recommendations": (
                self.gemma_result.to_dict() if self.gemma_result else None
            ),
            "verification": {
                "test_discovery": (
                    self.test_discovery.to_dict() if self.test_discovery else None
                ),
                "baseline_execution": (
                    self.baseline_result.to_dict() if self.baseline_result else None
                ),
                "replacement_experiments": [
                    r.to_dict() for r in self.replacement_results
                ],
            },
            "open_concerns_and_limitations": self._generate_limitations(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Return formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Generate human-readable, professional Markdown report."""
        data = self.to_dict()
        meta = data["metadata"]

        lines: List[str] = []
        lines.append(f"# Dependency Exit Capsule - {meta['repository_source']}")
        lines.append("")
        lines.append(f"**Generated:** `{meta['analysis_timestamp']}`  ")
        lines.append(f"**Repository Source:** `{meta['repository_source']}`  ")
        lines.append(f"**Commit:** `{meta['commit_hash']}`  ")
        lines.append(f"**Detected Ecosystems:** {', '.join(meta['detected_ecosystems']) or 'None'}  ")
        lines.append(f"**Manifest Files:** {', '.join(meta['manifest_files']) or 'None'}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 1. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(f"- **Total Dependencies Identified:** {meta['total_dependencies']}")
        lines.append(f"- **Total Risk Findings:** {meta['total_findings']}")
        lines.append(
            f"- **Severity Breakdown:** "
            f"Critical: {meta['severity_summary']['CRITICAL']}, "
            f"High: {meta['severity_summary']['HIGH']}, "
            f"Medium: {meta['severity_summary']['MEDIUM']}, "
            f"Low: {meta['severity_summary']['LOW']}"
        )
        ai_status = (
            "Available" if (self.gemma_result and self.gemma_result.success)
            else ("Not Configured (GEMMA_API_KEY missing)" if (self.gemma_result and not self.gemma_result.configured) else "Unavailable")
        )
        lines.append(f"- **Gemma 4 Risk Analysis:** {ai_status}")
        base_status = self.baseline_result.status if self.baseline_result else "NOT_TESTED"
        lines.append(f"- **Baseline Test Verification:** `{base_status}`")
        lines.append("")

        # 2. Risk Findings
        lines.append("## 2. Identified Dependency Risks")
        lines.append("")
        if not self.findings:
            lines.append("No dependency risks identified.")
        else:
            lines.append("| Package | Version | Severity | Category | Status | Evidence & Source |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in self.findings:
                lines.append(
                    f"| **{f.package_name}** | `{f.declared_version}` | `{f.severity}` | `{f.risk_category}` | `{f.status}` | {f.evidence} *(Source: {f.source})* |"
                )
        lines.append("")

        # 3. Usage Mapping
        lines.append("## 3. Dependency Usage Mapping (Source Code AST)")
        lines.append("")
        used_deps = [d for d in self.dependencies if d.usage_locations]
        if not used_deps:
            lines.append("No direct source code usages mapped for declared dependencies.")
        else:
            for d in used_deps:
                lines.append(f"### `{d.name}` ({len(d.usage_locations)} callsite{'s' if len(d.usage_locations) > 1 else ''})")
                for u in d.usage_locations:
                    lines.append(f"- `{u.file_path}:L{u.line_number}`: `{u.snippet}`")
                lines.append("")

        # 4. Gemma 4 Migration Recommendations
        lines.append("## 4. Gemma 4 Migration & Replacement Recommendations")
        lines.append("")
        if not self.gemma_result or not self.gemma_result.configured:
            lines.append("> [!NOTE]")
            lines.append("> Gemma 4 was not configured during this analysis run (`GEMMA_API_KEY` missing).")
            lines.append("> Deterministic scanning and inventory were completed without AI proposals.")
        elif not self.gemma_result.success:
            lines.append(f"> [!WARNING]\n> Gemma 4 analysis encountered an error: {self.gemma_result.error_message}")
        elif not self.gemma_result.recommendations:
            lines.append("Gemma 4 evaluated the evidence and proposed no active package migrations.")
        else:
            if self.gemma_result.general_guidance:
                lines.append(f"**Maintainer Guidance:** {self.gemma_result.general_guidance}\n")

            for r in self.gemma_result.recommendations:
                target_str = f" -> **{r.replacement_candidate}**" if r.replacement_candidate else " (Deprecation / Removal)"
                lines.append(f"### `{r.package_name}`{target_str} `[AI_RECOMMENDATION]`")
                lines.append(f"- **Risk Interpretation:** {r.risk_summary}")
                lines.append(f"- **Rationale:** {r.rationale}")
                if r.migration_steps:
                    lines.append("- **Migration Steps:**")
                    for s in r.migration_steps:
                        lines.append(f"  1. {s}")
                if r.suggested_tests:
                    lines.append("- **Suggested Compatibility Tests:**")
                    for t in r.suggested_tests:
                        lines.append(f"  - {t}")
                if r.compatibility_concerns:
                    lines.append(f"- **Compatibility Concerns:** {r.compatibility_concerns}")
                if r.uncertainty:
                    lines.append(f"- **Uncertainty / Maintainer Note:** {r.uncertainty}")
                lines.append("")

        # 5. Verification Results
        lines.append("## 5. Execution Verification Results")
        lines.append("")
        if not self.baseline_result:
            lines.append("No baseline test execution was attempted (`NOT_TESTED`).")
        else:
            lines.append(f"- **Baseline Test Status:** `{self.baseline_result.status}`")
            lines.append(f"- **Command:** `{' '.join(self.baseline_result.command)}`")
            lines.append(f"- **Exit Code:** `{self.baseline_result.exit_code}`")
            lines.append(f"- **Duration:** `{self.baseline_result.duration_ms} ms`")
            if self.baseline_result.error_message:
                lines.append(f"- **Notes:** {self.baseline_result.error_message}")

        lines.append("")
        if self.replacement_results:
            lines.append("### Replacement Experiments")
            for rep in self.replacement_results:
                lines.append(f"- **Experiment:** `{rep.target_package}` -> `{rep.replacement_package}`: Status `{rep.status}`")
                lines.append(f"  - Baseline: `{rep.baseline_status}` | Replacement: `{rep.replacement_status}`")
                lines.append(f"  - Notes: {rep.notes}")
                if rep.compatibility_gaps:
                    for g in rep.compatibility_gaps:
                        lines.append(f"  - Gap: {g}")
            lines.append("")

        # 6. Dependency Inventory
        lines.append("## 6. Complete Dependency Inventory")
        lines.append("")
        lines.append("| Name | Ecosystem | Type | Declared Constraint | Manifest | Usages |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for d in self.dependencies:
            lines.append(
                f"| `{d.name}` | {d.ecosystem} | {d.dep_type} | `{d.version_spec}` | `{d.manifest_file}` | {len(d.usage_locations)} |"
            )
        lines.append("")

        # 7. Limitations & Security Guardrails
        lines.append("## 7. Limitations & Security Guardrails")
        lines.append("")
        for lim in data["open_concerns_and_limitations"]:
            lines.append(f"- {lim}")
        lines.append("")

        return "\n".join(lines)

    def export_files(self, output_dir: Path) -> Tuple[Path, Path]:
        """Write capsule to dependency_exit_capsule.json and dependency_exit_capsule.md."""
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "dependency_exit_capsule.json"
        md_path = output_dir / "dependency_exit_capsule.md"

        json_path.write_text(self.to_json(), encoding="utf-8")
        md_path.write_text(self.to_markdown(), encoding="utf-8")

        return json_path, md_path

    def _generate_limitations(self) -> List[str]:
        """Produce factual limitations and security disclaimers."""
        return [
            "AI recommendations from Gemma 4 represent architectural guidance and must be validated through test suites before production deployment.",
            "Execution verification operates within subprocess boundaries; Python virtual environments alone do not provide kernel-level security isolation.",
            "Repository source code is treated as untrusted; code execution is strictly opt-in and requires explicit maintainer authorization.",
            "Dynamic imports (e.g. __import__, importlib) or runtime reflection cannot be detected purely via static AST analysis.",
        ]
