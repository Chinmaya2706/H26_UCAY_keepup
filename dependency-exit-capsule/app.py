"""Dependency Exit Capsule — Lightweight AI Developer Tool Streamlit Application."""

import os
import sys
from pathlib import Path
from typing import List, Optional

import streamlit as st
from dotenv import load_dotenv

load_dotenv(override=True)  # Load .env before any os.getenv() calls

# Ensure repository root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.capsule import CapsuleExporter
from core.gemma import GemmaAnalysisResult, GemmaClient
from core.verifier import ExecutionResult, ReplacementVerificationResult, TestDiscovery, TestVerifier
from scanners.javascript_scanner import JavaScriptScanner
from scanners.models import DependencyItem, RiskFinding
from scanners.python_scanner import PythonScanner
from scanners.repository import RepositoryError, RepositoryInfo, RepositoryManager

st.set_page_config(
    page_title="Dependency Exit Capsule",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def init_session_state():
    """Initialize Streamlit session state variables."""
    defaults = {
        "analyzed": False,
        "repo_info": None,
        "dependencies": [],
        "findings": [],
        "import_usages": {},
        "gemma_result": None,
        "test_discovery": None,
        "baseline_result": None,
        "replacement_results": [],
        "capsule_json": "",
        "capsule_md": "",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


init_session_state()

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.title("🛡️ Exit Capsule")
    st.markdown("**Lightweight AI Developer Tool**")
    st.caption("Identify dependency risks, map AST usages, get Gemma 4 migration plans, and verify via execution.")
    st.markdown("---")

    st.subheader("Gemma 4 Configuration")
    gemma_api_key = st.text_input(
        "Gemma API Key",
        value=os.getenv("GEMMA_API_KEY", ""),
        type="password",
        help="Optional API key for Gemma 4 (OpenRouter, Groq, or Google AI Studio).",
    )
    gemma_model = st.text_input(
        "Model Name",
        value=os.getenv("GEMMA_MODEL", "gemma-4-it"),
        help="Target model identifier (e.g. gemma-4-it, google/gemma-2-9b-it).",
    )
    gemma_base_url = st.text_input(
        "Inference Base URL",
        value=os.getenv("GEMMA_BASE_URL", "https://openrouter.ai/api/v1"),
        help="OpenAI-compatible base URL or Google AI Studio endpoint.",
    )

    if gemma_api_key.strip():
        st.success("🟢 Gemma 4 API configured")
    else:
        st.info("⚪ Gemma 4 key not set (deterministic scan will proceed without AI)")

    st.markdown("---")
    st.markdown("### Status Taxonomy")
    st.markdown(
        """
        - `OBSERVED`: Manifest or AST fact
        - `EXTERNALLY_VERIFIED`: Registry / advisory fact
        - `AI_RECOMMENDATION`: Gemma 4 migration proposal
        - `EXECUTION_VERIFIED`: Real test passed
        - `FAILED`: Test failed during run
        - `NOT_TESTED`: Verification skipped
        - `UNKNOWN`: Unconfirmed status
        """
    )


# ----------------- MAIN UI -----------------
st.title("Dependency Exit Capsule")
st.markdown(
    "Automated dependency risk scanner, AST usage mapper, Gemma 4 migration assistant, and execution verifier."
)

with st.container():
    col1, col2 = st.columns([3, 2])
    with col1:
        repo_url = st.text_input(
            "GitHub Repository URL",
            value="https://github.com/rishrek/LinkWatch",
            placeholder="https://github.com/owner/repository",
            help="Public GitHub repository URL to clone and analyze.",
        )
    with col2:
        local_path = st.text_input(
            "Or Local Repository Path",
            value="",
            placeholder="e.g. C:/Projects/my-app",
            help="Optional local path to analyze directly without cloning.",
        )

    analyze_clicked = st.button("🚀 Analyze Repository", type="primary", use_container_width=True)

# ----------------- ANALYSIS PIPELINE -----------------
if analyze_clicked:
    target_source = local_path.strip() if local_path.strip() else repo_url.strip()
    if not target_source:
        st.error("Please enter a valid GitHub URL or local repository path.")
    else:
        with st.status("Analyzing repository...", expanded=True) as status_box:
            try:
                # 1. Repository inspection and cloning
                st.write("🔍 Inspecting repository & detecting ecosystems...")
                repo_mgr = RepositoryManager(target_source)
                repo_info = repo_mgr.prepare()
                st.session_state.repo_info = repo_info

                if repo_info.is_empty:
                    st.warning("Repository appears to be empty. No files to scan.")
                    status_box.update(label="Analysis stopped (empty repository)", state="error")
                    st.stop()

                # 2. Dependency scanning and AST usage mapping
                all_dependencies: List[DependencyItem] = []
                all_findings: List[RiskFinding] = []
                all_import_usages = {}

                if "python" in repo_info.detected_ecosystems:
                    st.write("🐍 Parsing Python manifests and tracing AST imports...")
                    py_scanner = PythonScanner(repo_info.local_path)
                    py_deps, py_findings, py_usages = py_scanner.scan()
                    all_dependencies.extend(py_deps)
                    all_findings.extend(py_findings)
                    all_import_usages.update(py_usages)

                if "javascript" in repo_info.detected_ecosystems:
                    st.write("📦 Parsing JavaScript/TypeScript package.json and scanning source imports...")
                    js_scanner = JavaScriptScanner(repo_info.local_path)
                    js_deps, js_findings, js_usages = js_scanner.scan()
                    all_dependencies.extend(js_deps)
                    all_findings.extend(js_findings)
                    all_import_usages.update(js_usages)

                st.session_state.dependencies = all_dependencies
                st.session_state.findings = all_findings
                st.session_state.import_usages = all_import_usages

                # 3. Test discovery
                st.write("🧪 Discovering test suite and configuration...")
                verifier = TestVerifier(repo_info.local_path)
                test_discovery = verifier.discover_tests(repo_info.detected_ecosystems)
                st.session_state.test_discovery = test_discovery

                # 4. Gemma 4 AI Analysis
                st.write("🤖 Invoking Gemma 4 for migration recommendations...")
                gemma_client = GemmaClient(
                    api_key=gemma_api_key.strip() or None,
                    model=gemma_model.strip() or None,
                    base_url=gemma_base_url.strip() or None,
                )
                gemma_result = gemma_client.analyze_dependencies(
                    repo_source=repo_info.source,
                    ecosystem=", ".join(repo_info.detected_ecosystems),
                    dependencies=all_dependencies,
                    findings=all_findings,
                )
                st.session_state.gemma_result = gemma_result

                # 5. Build initial Capsule
                exporter = CapsuleExporter(
                    repo_info=repo_info,
                    dependencies=all_dependencies,
                    findings=all_findings,
                    gemma_result=gemma_result,
                    test_discovery=test_discovery,
                )
                st.session_state.capsule_json = exporter.to_json()
                st.session_state.capsule_md = exporter.to_markdown()
                st.session_state.baseline_result = None
                st.session_state.replacement_results = []
                st.session_state.analyzed = True

                status_box.update(label="Analysis completed successfully!", state="complete")
            except RepositoryError as e:
                st.error(f"Repository Error: {str(e)}")
                status_box.update(label="Analysis failed", state="error")
            except Exception as e:
                st.error(f"Unexpected Error during analysis: {str(e)}")
                status_box.update(label="Analysis failed", state="error")


# ----------------- RESULTS DASHBOARD -----------------
if st.session_state.analyzed and st.session_state.repo_info:
    repo_info: RepositoryInfo = st.session_state.repo_info
    dependencies: List[DependencyItem] = st.session_state.dependencies
    findings: List[RiskFinding] = st.session_state.findings
    gemma_result: Optional[GemmaAnalysisResult] = st.session_state.gemma_result
    test_discovery: Optional[TestDiscovery] = st.session_state.test_discovery

    st.markdown("---")

    # Header Badges & Metrics
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Dependencies", len(dependencies))
    with m2:
        high_crit = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
        st.metric("High/Critical Risks", high_crit)
    with m3:
        med_low = sum(1 for f in findings if f.severity in ("MEDIUM", "LOW"))
        st.metric("Med/Low Risks", med_low)
    with m4:
        usages_count = sum(len(d.usage_locations) for d in dependencies)
        st.metric("Source Usages Mapped", usages_count)
    with m5:
        eco_str = ", ".join(repo_info.detected_ecosystems).upper() if repo_info.detected_ecosystems else "NONE"
        st.metric("Ecosystems", eco_str)

    if repo_info.warning:
        st.warning(repo_info.warning)

    # Tabs for structured navigation
    tab_risks, tab_gemma, tab_usages, tab_verify, tab_inventory, tab_capsule = st.tabs([
        "⚠️ Risk Findings",
        "🤖 Gemma 4 Recommendations",
        "📍 AST Usage Mapping",
        "🧪 Verification Engine",
        "📋 Dependency Inventory",
        "📥 Download Exit Capsule",
    ])

    # 1. RISK FINDINGS TAB
    with tab_risks:
        st.subheader("Identified Dependency Risks")
        if not findings:
            st.success("No dependency risks identified in declared manifests.")
        else:
            for f in findings:
                sev_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                    "INFO": "gray",
                }.get(f.severity, "gray")

                with st.expander(f"**{f.package_name}** ({f.declared_version}) — :{sev_color}[{f.severity}] {f.risk_category} `[{f.status}]`"):
                    st.markdown(f"**Evidence:** {f.evidence}")
                    st.markdown(f"**Source:** `{f.source}`")
                    st.markdown(f"**Category:** `{f.risk_category}` | **Status:** `{f.status}`")
                    if f.details:
                        st.json(f.details)

    # 2. GEMMA 4 RECOMMENDATIONS TAB
    with tab_gemma:
        st.subheader("Gemma 4 Migration & Replacement Proposals")
        if not gemma_result:
            st.info("No Gemma 4 analysis performed.")
        elif not gemma_result.configured:
            st.info(f"ℹ️ {gemma_result.error_message}")
        elif not gemma_result.success:
            st.error(f"⚠️ Gemma 4 Error: {gemma_result.error_message}")
        else:
            if gemma_result.general_guidance:
                st.info(f"**Maintainer Strategy:** {gemma_result.general_guidance}")

            if not gemma_result.recommendations:
                st.write("Gemma 4 evaluated the dependencies and recommended no package replacements.")
            else:
                for rec in gemma_result.recommendations:
                    title = f"Migrate `{rec.package_name}` -> **`{rec.replacement_candidate}`**" if rec.replacement_candidate else f"Address `{rec.package_name}`"
                    with st.container(border=True):
                        st.markdown(f"#### {title} `[{rec.status}]`")
                        st.markdown(f"**Risk Summary:** {rec.risk_summary}")
                        st.markdown(f"**Rationale:** {rec.rationale}")

                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.markdown("**Actionable Migration Steps:**")
                            for step in rec.migration_steps:
                                st.markdown(f"- {step}")
                        with col_b:
                            st.markdown("**Suggested Validation Tests:**")
                            for test in rec.suggested_tests:
                                st.markdown(f"- {test}")

                        if rec.compatibility_concerns:
                            st.warning(f"**Compatibility Concerns:** {rec.compatibility_concerns}")
                        if rec.uncertainty:
                            st.caption(f"**Uncertainty / Maintainer Note:** {rec.uncertainty}")

    # 3. AST USAGE MAPPING TAB
    with tab_usages:
        st.subheader("Source Code Usage Mapping (AST)")
        st.caption("Traces exact file paths, line numbers, and snippets where dependencies are imported.")
        used_deps = [d for d in dependencies if d.usage_locations]
        if not used_deps:
            st.write("No imported dependencies mapped in repository source files.")
        else:
            for dep in used_deps:
                with st.expander(f"📦 `{dep.name}` ({len(dep.usage_locations)} callsite{'s' if len(dep.usage_locations) > 1 else ''})"):
                    for u in dep.usage_locations:
                        st.markdown(f"- `{u.file_path}:L{u.line_number}`: `{u.snippet}`")

    # 4. VERIFICATION ENGINE TAB
    with tab_verify:
        st.subheader("Test Execution & Replacement Verification")
        if not test_discovery or not test_discovery.available:
            st.info("No supported test framework discovered in this repository.")
        else:
            st.success(f"**Discovered:** {test_discovery.description}")
            st.code(" ".join(test_discovery.command_args), language="bash")

            st.warning(
                "⚠️ **Security Notice:** Executing repository code runs code from potentially untrusted sources. "
                "Verification is strictly opt-in and requires explicit authorization."
            )
            authorize = st.checkbox("I explicitly authorize executing tests for this repository.", value=False)

            v_col1, v_col2 = st.columns(2)

            with v_col1:
                st.markdown("### 1. Baseline Test Run")
                if st.button("▶️ Run Baseline Tests", disabled=not authorize):
                    with st.spinner("Running baseline tests in repository..."):
                        verifier = TestVerifier(repo_info.local_path)
                        base_res = verifier.run_baseline_tests(test_discovery, user_authorized=authorize)
                        st.session_state.baseline_result = base_res

                        # Refresh capsule with new test result
                        exp = CapsuleExporter(
                            repo_info=repo_info,
                            dependencies=dependencies,
                            findings=findings,
                            gemma_result=gemma_result,
                            test_discovery=test_discovery,
                            baseline_result=base_res,
                            replacement_results=st.session_state.replacement_results,
                        )
                        st.session_state.capsule_json = exp.to_json()
                        st.session_state.capsule_md = exp.to_markdown()

                if st.session_state.baseline_result:
                    b_res = st.session_state.baseline_result
                    status_badge = "🟢 PASSED" if b_res.status == "PASSED" else f"🔴 {b_res.status}"
                    st.markdown(f"**Status:** `{status_badge}` | **Duration:** {b_res.duration_ms} ms")
                    if b_res.stdout_summary:
                        with st.expander("Stdout Summary"):
                            st.text(b_res.stdout_summary)
                    if b_res.stderr_summary:
                        with st.expander("Stderr Summary"):
                            st.text(b_res.stderr_summary)

            with v_col2:
                st.markdown("### 2. Replacement Compatibility Experiment")
                st.caption("Attempts safe, isolated migration experiment on a temporary copy.")

                # Populate replacement candidates from findings/Gemma
                default_target = "appdirs" if any(d.name.lower() == "appdirs" for d in dependencies) else (dependencies[0].name if dependencies else "")
                target_pkg = st.text_input("Target Package to Replace", value=default_target)
                repl_pkg = st.text_input("Replacement Package", value="platformdirs")

                if st.button("🧪 Run Replacement Experiment", disabled=not authorize):
                    with st.spinner(f"Testing isolated migration {target_pkg} -> {repl_pkg}..."):
                        verifier = TestVerifier(repo_info.local_path)
                        repl_res = verifier.run_replacement_experiment(
                            target_package=target_pkg,
                            replacement_package=repl_pkg,
                            discovery=test_discovery,
                            user_authorized=authorize,
                        )
                        st.session_state.replacement_results.append(repl_res)

                        # Refresh capsule
                        exp = CapsuleExporter(
                            repo_info=repo_info,
                            dependencies=dependencies,
                            findings=findings,
                            gemma_result=gemma_result,
                            test_discovery=test_discovery,
                            baseline_result=st.session_state.baseline_result,
                            replacement_results=st.session_state.replacement_results,
                        )
                        st.session_state.capsule_json = exp.to_json()
                        st.session_state.capsule_md = exp.to_markdown()

                if st.session_state.replacement_results:
                    for rep in st.session_state.replacement_results:
                        st.markdown(f"**{rep.target_package} -> {rep.replacement_package}:** `{rep.status}`")
                        st.caption(f"{rep.notes}")
                        if rep.compatibility_gaps:
                            for gap in rep.compatibility_gaps:
                                st.error(gap)

    # 5. DEPENDENCY INVENTORY TAB
    with tab_inventory:
        st.subheader("Complete Dependency Inventory")
        inv_data = [
            {
                "Package": d.name,
                "Ecosystem": d.ecosystem,
                "Type": d.dep_type,
                "Constraint": d.version_spec,
                "Manifest": d.manifest_file,
                "Usages": len(d.usage_locations),
            }
            for d in dependencies
        ]
        st.dataframe(inv_data, use_container_width=True)

    # 6. DOWNLOAD CAPSULE TAB
    with tab_capsule:
        st.subheader("Export Dependency Exit Capsule")
        st.markdown(
            "Download standardized, machine-readable and human-readable audit capsules containing all observed facts, "
            "AI proposals, and execution results."
        )

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.download_button(
                label="📄 Download Capsule (Markdown)",
                data=st.session_state.capsule_md,
                file_name="dependency_exit_capsule.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with d_col2:
            st.download_button(
                label="📦 Download Capsule (JSON)",
                data=st.session_state.capsule_json,
                file_name="dependency_exit_capsule.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")
        prev_md, prev_json = st.tabs(["Markdown Preview", "JSON Preview"])
        with prev_md:
            st.markdown(st.session_state.capsule_md)
        with prev_json:
            st.code(st.session_state.capsule_json, language="json")
