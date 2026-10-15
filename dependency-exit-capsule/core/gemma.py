"""Gemma 4 AI integration for dependency risk analysis and replacement recommendations."""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

from scanners.models import DependencyItem, RiskFinding

# Load .env if present
load_dotenv()


@dataclass
class GemmaRecommendation:
    """A structured migration recommendation produced by Gemma 4."""

    package_name: str
    replacement_candidate: Optional[str]
    risk_summary: str
    rationale: str
    migration_steps: List[str] = field(default_factory=list)
    suggested_tests: List[str] = field(default_factory=list)
    compatibility_concerns: str = ""
    uncertainty: str = ""
    status: str = "AI_RECOMMENDATION"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "replacement_candidate": self.replacement_candidate,
            "risk_summary": self.risk_summary,
            "rationale": self.rationale,
            "migration_steps": self.migration_steps,
            "suggested_tests": self.suggested_tests,
            "compatibility_concerns": self.compatibility_concerns,
            "uncertainty": self.uncertainty,
            "status": self.status,
        }


@dataclass
class GemmaAnalysisResult:
    """Result of invoking Gemma 4 analysis."""

    success: bool
    configured: bool
    model_name: str
    recommendations: List[GemmaRecommendation] = field(default_factory=list)
    general_guidance: str = ""
    raw_output: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "configured": self.configured,
            "model_name": self.model_name,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "general_guidance": self.general_guidance,
            "error_message": self.error_message,
        }


class GemmaClient:
    """Client for querying Gemma 4 via OpenAI-compatible or Google GenAI endpoints."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 45,
    ):
        self.api_key = api_key or os.getenv("GEMMA_API_KEY") or os.getenv("OPENROUTER_API_KEY") or os.getenv("GROQ_API_KEY")
        self.model = model or os.getenv("GEMMA_MODEL", "gemma-4-it")
        self.base_url = (base_url or os.getenv("GEMMA_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
        self.timeout = timeout

    def is_configured(self) -> bool:
        """Check whether Gemma API key is configured."""
        return bool(self.api_key and self.api_key.strip())

    def analyze_dependencies(
        self,
        repo_source: str,
        ecosystem: str,
        dependencies: List[DependencyItem],
        findings: List[RiskFinding],
    ) -> GemmaAnalysisResult:
        """Perform substantive AI risk interpretation and replacement recommendation."""
        if not self.is_configured():
            return GemmaAnalysisResult(
                success=False,
                configured=False,
                model_name=self.model,
                recommendations=[],
                error_message=(
                    "Gemma 4 API credentials not configured (GEMMA_API_KEY). "
                    "Deterministic risk scanning and report generation proceed without AI recommendations. "
                    "To enable Gemma 4 migration proposals, configure GEMMA_API_KEY, GEMMA_MODEL, and GEMMA_BASE_URL in .env."
                ),
            )

        # Prepare compact, bounded evidence payload (avoid token waste, never send entire repo)
        payload_data = self._build_context_payload(repo_source, ecosystem, dependencies, findings)

        prompt = (
            "You are Gemma 4, an expert software architecture and dependency security model. "
            "Analyze the following repository dependency inventory, observed risks, and source code usage locations.\n"
            "Distinguish observed evidence from speculation. All recommendations must be actionable suggestions for a maintainer.\n\n"
            f"REPOSITORY CONTEXT & EVIDENCE:\n{json.dumps(payload_data, indent=2)}\n\n"
            "Respond ONLY with a valid JSON object matching this exact schema:\n"
            "{\n"
            '  "recommendations": [\n'
            "    {\n"
            '      "package_name": "<exact name of risky/deprecated package>",\n'
            '      "replacement_candidate": "<exact replacement package or null>",\n'
            '      "risk_summary": "<interpretation of observed evidence>",\n'
            '      "rationale": "<why the replacement is suitable or why package should be removed>",\n'
            '      "migration_steps": ["<step 1>", "<step 2>"],\n'
            '      "suggested_tests": ["<test 1>", "<test 2>"],\n'
            '      "compatibility_concerns": "<API differences or behavioral gotchas>",\n'
            '      "uncertainty": "<unresolved risks or verification requirements>"\n'
            "    }\n"
            "  ],\n"
            '  "general_guidance": "<high-level summary of repository health and migration sequence>"\n'
            "}\n"
        )

        try:
            raw_response = self._call_model(prompt)
            parsed_data = self._parse_json_response(raw_response)
            recs = self._extract_recommendations(parsed_data)
            guidance = parsed_data.get("general_guidance", "")

            return GemmaAnalysisResult(
                success=True,
                configured=True,
                model_name=self.model,
                recommendations=recs,
                general_guidance=guidance,
                raw_output=raw_response,
            )
        except Exception as e:
            return GemmaAnalysisResult(
                success=False,
                configured=True,
                model_name=self.model,
                error_message=f"Gemma 4 API request failed: {str(e)}",
            )

    def _build_context_payload(
        self,
        repo_source: str,
        ecosystem: str,
        dependencies: List[DependencyItem],
        findings: List[RiskFinding],
    ) -> Dict[str, Any]:
        """Construct bounded, token-efficient summary of evidence and usage."""
        # Focus on dependencies with risks or active usage
        risky_pkgs = {f.package_name.lower() for f in findings}

        dep_summaries = []
        for dep in dependencies:
            is_risky = dep.name.lower() in risky_pkgs
            # Bound usage snippets to 3 max per dependency
            limited_snippets = [
                f"{u.file_path}:{u.line_number} -> {u.snippet}"
                for u in dep.usage_locations[:3]
            ]
            dep_summaries.append({
                "name": dep.name,
                "version": dep.version_spec,
                "manifest": dep.manifest_file,
                "has_risk": is_risky,
                "usage_count": len(dep.usage_locations),
                "sample_usages": limited_snippets,
            })

        findings_summary = [
            {
                "package": f.package_name,
                "category": f.risk_category,
                "severity": f.severity,
                "evidence": f.evidence,
                "status": f.status,
            }
            for f in findings
        ]

        return {
            "repository": repo_source,
            "ecosystem": ecosystem,
            "total_dependencies": len(dependencies),
            "findings": findings_summary,
            "dependencies": dep_summaries[:25],  # Capped to avoid huge token bills
        }

    def _call_model(self, prompt: str) -> str:
        """Call LLM inference endpoint (OpenAI-compatible or Google AI Studio)."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # Handle OpenAI-compatible endpoints (OpenRouter, Groq, local Ollama/vLLM)
        url = f"{self.base_url}/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are Gemma 4, an automated software migration and dependency exit assistant. Always output strict JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        # Check for Google AI Studio style endpoint
        if "generativelanguage.googleapis.com" in self.base_url:
            url = f"{self.base_url}/v1beta/models/{self.model}:generateContent?key={self.api_key}"
            headers = {"Content-Type": "application/json"}
            body = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2},
            }

        response = requests.post(url, headers=headers, json=body, timeout=self.timeout)

        if response.status_code == 401:
            raise ValueError("Authentication error (401): Invalid GEMMA_API_KEY.")
        if response.status_code == 429:
            raise ValueError("Rate limit exceeded (429): Quota limit reached on Gemma endpoint.")
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}: {response.text[:200]}")

        res_json = response.json()

        # Parse OpenAI-compatible output
        if "choices" in res_json and res_json["choices"]:
            return res_json["choices"][0]["message"]["content"]

        # Parse Google AI Studio output
        if "candidates" in res_json and res_json["candidates"]:
            parts = res_json["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)

        raise ValueError(f"Unrecognized response format from endpoint: {res_json}")

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON from model output, handling markdown code fences."""
        cleaned = text.strip()
        # Remove ```json ... ``` markdown fences
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            # Fallback: find outer curly braces
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1:
                return json.loads(cleaned[start : end + 1])
            raise ValueError(f"Failed to parse valid JSON from Gemma response: {e}")

    def _extract_recommendations(self, data: Dict[str, Any]) -> List[GemmaRecommendation]:
        """Convert parsed JSON into validated GemmaRecommendation objects."""
        raw_recs = data.get("recommendations", [])
        recs: List[GemmaRecommendation] = []

        for item in raw_recs:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package_name") or "unknown"
            recs.append(
                GemmaRecommendation(
                    package_name=pkg,
                    replacement_candidate=item.get("replacement_candidate"),
                    risk_summary=item.get("risk_summary", ""),
                    rationale=item.get("rationale", ""),
                    migration_steps=item.get("migration_steps", []) or [],
                    suggested_tests=item.get("suggested_tests", []) or [],
                    compatibility_concerns=item.get("compatibility_concerns", ""),
                    uncertainty=item.get("uncertainty", ""),
                    status="AI_RECOMMENDATION",
                )
            )

        return recs
