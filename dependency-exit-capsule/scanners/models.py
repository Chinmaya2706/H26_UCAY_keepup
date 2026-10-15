"""Data models for dependencies, usage locations, and risk findings."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class UsageLocation:
    """Represents a specific source code location where a dependency is used."""

    file_path: str
    line_number: int
    snippet: str
    import_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "import_name": self.import_name,
        }


@dataclass
class DependencyItem:
    """A declared dependency identified in repository manifests."""

    name: str
    ecosystem: str
    version_spec: str
    manifest_file: str
    dep_type: str = "runtime"  # runtime, dev, optional, peer
    usage_locations: List[UsageLocation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "version_spec": self.version_spec,
            "manifest_file": self.manifest_file,
            "dep_type": self.dep_type,
            "usage_count": len(self.usage_locations),
            "usage_locations": [u.to_dict() for u in self.usage_locations],
        }


@dataclass
class RiskFinding:
    """An identified risk for a dependency, backed by evidence."""

    package_name: str
    declared_version: str
    ecosystem: str
    risk_category: str  # UNPINNED_DEPENDENCY, LOOSE_CONSTRAINT, MANIFEST_CONFLICT, DEPRECATED_PACKAGE, KNOWN_VULNERABILITY, UNUSED_DEPENDENCY, UNDECLARED_IMPORT
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    evidence: str
    source: str
    status: str = "OBSERVED"  # OBSERVED, EXTERNALLY_VERIFIED, UNKNOWN
    cve_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "declared_version": self.declared_version,
            "ecosystem": self.ecosystem,
            "risk_category": self.risk_category,
            "severity": self.severity,
            "evidence": self.evidence,
            "source": self.source,
            "status": self.status,
            "cve_ids": self.cve_ids,
            "details": self.details,
        }
