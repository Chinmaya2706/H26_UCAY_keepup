"""Unit tests for Dependency Exit Capsule generation and Gemma 4 configuration handling."""

import json
import tempfile
from pathlib import Path

from core.capsule import CapsuleExporter
from core.gemma import GemmaAnalysisResult, GemmaClient, GemmaRecommendation
from core.verifier import ExecutionResult, ReplacementVerificationResult, TestDiscovery, TestVerifier
from scanners.models import DependencyItem, RiskFinding, UsageLocation
from scanners.repository import RepositoryInfo


def test_capsule_json_and_markdown_generation():
    """Verify that both JSON and Markdown capsule outputs are valid, structured, and complete."""
    repo_info = RepositoryInfo(
        source="https://github.com/example/sample-repo",
        is_remote=True,
        local_path=Path("/tmp/sample"),
        detected_ecosystems=["python"],
        manifest_files=["requirements.txt"],
        commit_hash="abc1234",
    )

    dep = DependencyItem(
        name="appdirs",
        ecosystem="python",
        version_spec="==1.4.4",
        manifest_file="requirements.txt",
        dep_type="runtime",
        usage_locations=[
            UsageLocation(
                file_path="app/cache.py",
                line_number=10,
                snippet="from appdirs import user_cache_dir",
                import_name="appdirs",
            )
        ],
    )

    finding = RiskFinding(
        package_name="appdirs",
        declared_version="==1.4.4",
        ecosystem="python",
        risk_category="DEPRECATED_PACKAGE",
        severity="HIGH",
        evidence="Package unmaintained since 2020.",
        source="requirements.txt:L1",
        status="EXTERNALLY_VERIFIED",
    )

    gemma_result = GemmaAnalysisResult(
        success=True,
        configured=True,
        model_name="gemma-4-it",
        recommendations=[
            GemmaRecommendation(
                package_name="appdirs",
                replacement_candidate="platformdirs",
                risk_summary="appdirs is abandoned.",
                rationale="platformdirs is the actively maintained successor.",
                migration_steps=["Replace appdirs with platformdirs>=4.0.0 in requirements.txt"],
                suggested_tests=["Run test_cache.py to verify cache path resolution"],
                compatibility_concerns="Minimal API divergence for user_cache_dir.",
                uncertainty="Verify path resolution across operating systems.",
                status="AI_RECOMMENDATION",
            )
        ],
        general_guidance="Upgrade abandoned dependencies first.",
    )

    test_disc = TestDiscovery(
        framework="pytest",
        command_args=["python", "-m", "pytest", "tests"],
        test_files=["tests/test_sample.py"],
        available=True,
    )

    base_res = ExecutionResult(
        command=["python", "-m", "pytest", "tests"],
        exit_code=0,
        duration_ms=450,
        status="PASSED",
        stdout_summary="1 passed in 0.45s",
    )

    repl_res = ReplacementVerificationResult(
        target_package="appdirs",
        replacement_package="platformdirs",
        experiment_attempted=True,
        status="EXECUTION_VERIFIED",
        baseline_status="PASSED",
        replacement_status="PASSED",
        notes="All unit tests passed with replacement import.",
    )

    exporter = CapsuleExporter(
        repo_info=repo_info,
        dependencies=[dep],
        findings=[finding],
        gemma_result=gemma_result,
        test_discovery=test_disc,
        baseline_result=base_res,
        replacement_results=[repl_res],
    )

    # 1. Test JSON validity
    json_str = exporter.to_json()
    parsed = json.loads(json_str)
    assert parsed["metadata"]["repository_source"] == "https://github.com/example/sample-repo"
    assert parsed["metadata"]["total_dependencies"] == 1
    assert parsed["metadata"]["total_findings"] == 1
    assert "status_taxonomy" in parsed
    assert "OBSERVED" in parsed["status_taxonomy"]
    assert "EXECUTION_VERIFIED" in parsed["status_taxonomy"]
    assert len(parsed["gemma_recommendations"]["recommendations"]) == 1

    # 2. Test Markdown content
    md_str = exporter.to_markdown()
    assert "# Dependency Exit Capsule" in md_str
    assert "appdirs" in md_str
    assert "platformdirs" in md_str
    assert "AI_RECOMMENDATION" in md_str
    assert "EXECUTION_VERIFIED" in md_str
    assert "app/cache.py:L10" in md_str

    # 3. Test export to files
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir)
        j_file, m_file = exporter.export_files(out_path)
        assert j_file.is_file()
        assert m_file.is_file()
        assert j_file.stat().st_size > 0
        assert m_file.stat().st_size > 0


def test_missing_gemma_configuration():
    """Verify clean behavior when Gemma credentials are not provided."""
    client = GemmaClient(api_key="")
    assert client.is_configured() is False

    result = client.analyze_dependencies(
        repo_source="test/repo",
        ecosystem="python",
        dependencies=[],
        findings=[],
    )
    assert result.success is False
    assert result.configured is False
    assert "not configured" in result.error_message.lower()
    assert len(result.recommendations) == 0


def test_verifier_authorization_guardrail():
    """Verify that unauthenticated test execution is rejected with NOT_AUTHORIZED."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        repo = Path(tmp_dir)
        discovery = TestDiscovery(
            framework="pytest",
            command_args=["python", "-m", "pytest"],
            available=True,
        )
        verifier = TestVerifier(repo)

        # Baseline execution without authorization
        res = verifier.run_baseline_tests(discovery, user_authorized=False)
        assert res.status == "NOT_AUTHORIZED"
        assert "authorization is required" in res.error_message.lower()

        # Replacement experiment without authorization
        repl = verifier.run_replacement_experiment(
            target_package="pkg_a",
            replacement_package="pkg_b",
            discovery=discovery,
            user_authorized=False,
        )
        assert repl.status == "NOT_TESTED"
        assert repl.baseline_status == "NOT_AUTHORIZED"
