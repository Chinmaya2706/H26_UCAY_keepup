# Dependency Exit Capsule — Lightweight AI Developer Tool

A complete, runnable, lightweight developer tool that identifies dependency risks in GitHub repositories, traces source code imports via AST inspection, leverages **Gemma 4** for migration and replacement recommendations, verifies findings through real test execution in isolated environments, and exports a standardized **Dependency Exit Capsule** in Markdown and JSON.

Built for **Python 3.12 and 3.13** using only a lightweight stack (Streamlit, standard library `ast`, `pathlib`, `tomllib`, `subprocess`, `requests`, `pytest`).

---

## Key Features

1. **Repository Ingestion & Ecosystem Detection**
   - Ingests public GitHub repository URLs (`https://github.com/owner/repo`) or local repository paths.
   - Clones into isolated temporary directories using Git with timeout and network failure guards.
   - Detects multiple ecosystems dynamically:
     - **Python**: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `poetry.lock`.
     - **JavaScript / TypeScript**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.

2. **Real Dependency Risk Scanner**
   - **Manifest Conflict Detection**: Identifies cross-manifest discrepancies (e.g. `pydantic==1.10.13` in `requirements.txt` vs `pydantic>=2` in `pyproject.toml`).
   - **AST-Based Source Code Inspection**: Walks abstract syntax trees (`ast.walk`) to identify real imports, avoiding fake keyword matches.
   - **Import-to-Package Mapping**: Accurately resolves import aliases (e.g. `dateutil` -> `python-dateutil`, `pkg_resources` -> `setuptools`, `yaml` -> `PyYAML`).
   - **Risk Classification**:
     - `UNPINNED_DEPENDENCY`: Packages missing version constraints.
     - `LOOSE_CONSTRAINT`: Unbounded lower bounds (e.g. `click>=7`).
     - `MANIFEST_CONFLICT`: Incompatible version declarations across manifest files.
     - `DEPRECATED_PACKAGE`: Documented abandoned or sunset packages (e.g. `appdirs`, `toml` on Python 3.11+, `six`).
     - `UNUSED_DEPENDENCY`: Packages declared in manifests but absent from source code imports.
     - `UNDECLARED_IMPORT`: Third-party packages imported in source files but absent from manifests.

3. **Substantive Gemma 4 AI Migration Recommendations**
   - Core module `core/gemma.py` sends bounded evidence (package metadata, risk indicators, usage snippets) to Gemma 4.
   - Requests structured JSON responses including:
     - Risk interpretation
     - Suitable replacement candidates
     - Step-by-step maintainer migration instructions
     - Suggested regression/compatibility tests
     - Known behavioral or API gotchas
     - Uncertainty and verification requirements
   - **Honest Fallback**: When `GEMMA_API_KEY` is not configured or network access is unavailable, the application transparently reports configuration status and continues deterministic scanning without fabricating AI responses.

4. **Verification Engine & Security Guardrails**
   - Discovers repository test frameworks (`pytest`, `unittest`, `npm test`).
   - **Strict Opt-In Execution**: Cloned repositories are untrusted. Repository code and tests are **never** executed without explicit maintainer authorization.
   - **Baseline Test Execution**: Runs discovered test commands with configurable timeouts, capturing exit codes, durations, and bounded stdout/stderr.
   - **Isolated Replacement Experimentation**: Copies repository to a clean temporary directory, applies migration patches (e.g., `appdirs` -> `platformdirs`), executes test suites, and compares results to verify compatibility.
   - Documents that Python virtual environments alone do not constitute kernel-level security isolation.

5. **Dependency Exit Capsule Export**
   - Generates two standardized, reusable audit artifacts:
     - `dependency_exit_capsule.md` (Human-readable Markdown report)
     - `dependency_exit_capsule.json` (Machine-readable structured schema)
   - Adheres to strict status taxonomy:
     - `OBSERVED`: Static facts extracted from manifests and AST.
     - `EXTERNALLY_VERIFIED`: Confirmed by ecosystem deprecation advisories.
     - `AI_RECOMMENDATION`: Migration plan proposed by Gemma 4.
     - `EXECUTION_VERIFIED`: Validated by real passing tests in an isolated environment.
     - `FAILED`: Execution test failed.
     - `NOT_TESTED`: Verification withheld or skipped.
     - `UNKNOWN`: Unconfirmed status.

---

## Project Structure

```
dependency-exit-capsule/
├── app.py                      # Streamlit interactive web application
├── requirements.txt            # Python dependencies (Streamlit, pytest, requests, python-dotenv)
├── README.md                   # Complete architectural and operational documentation
├── .env.example                # Sample environment configuration for Gemma 4
├── .gitignore                  # Git ignore rules for virtualenvs, caches, and artifacts
├── scanners/
│   ├── __init__.py             # Scanners package initializer
│   ├── models.py               # Dataclasses: DependencyItem, RiskFinding, UsageLocation
│   ├── repository.py           # Repository cloning, validation, and ecosystem detection
│   ├── python_scanner.py       # Python manifest parsing, AST inspection, risk analysis
│   └── javascript_scanner.py   # JS/TS package.json parser, regex import scanner, risk analysis
├── core/
│   ├── __init__.py             # Core package initializer
│   ├── gemma.py                # Gemma 4 LLM client with structured prompts & fallbacks
│   ├── verifier.py             # Test discovery, baseline runner, replacement experiments
│   └── capsule.py              # Exporter for dependency_exit_capsule.md and .json
└── tests/
    ├── test_scanners.py        # Fixture-based unit tests for Python/JS scanners & empty repos
    └── test_capsule.py         # Unit tests for capsule generator, Gemma fallback, & guardrails
```

---

## Installation & Setup

### Prerequisites
- **Python 3.12 or 3.13**
- **Git CLI** (installed and available in `PATH`)

### 1. Clone & Enter Project
```bash
git clone <this-repository>
cd dependency-exit-capsule
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Linux/macOS:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env` to configure your preferred Gemma 4 endpoint:
```env
# OpenRouter (default):
GEMMA_API_KEY=sk-or-v1-...
GEMMA_MODEL=gemma-4-it
GEMMA_BASE_URL=https://openrouter.ai/api/v1

# Groq:
# GEMMA_API_KEY=gsk_...
# GEMMA_MODEL=gemma2-9b-it
# GEMMA_BASE_URL=https://api.groq.com/openai/v1

# Local Ollama / vLLM:
# GEMMA_API_KEY=ollama
# GEMMA_MODEL=gemma2:9b
# GEMMA_BASE_URL=http://localhost:11434/v1
```

> **Note:** If no API key is provided, the application runs fully in deterministic offline mode. Scanners, AST usage mappers, test verifiers, and capsule generation continue normally without AI speculation.

---

## Running the Application

Launch the Streamlit web dashboard:
```bash
streamlit run app.py
```

The application opens in your default browser at `http://localhost:8501`.

### Web Dashboard Workflow:
1. Enter a GitHub repository URL (e.g. `https://github.com/rishrek/LinkWatch`) or a local directory path.
2. Click **Analyze Repository**.
3. Inspect the **Risk Findings**, **AST Usage Mapping**, and **Gemma 4 Recommendations**.
4. Switch to the **Verification Engine** tab, check the authorization checkbox, and run baseline or replacement experiments.
5. Download the complete **Dependency Exit Capsule** in Markdown or JSON format.

---

## Testing

Run the automated test suite:
```bash
pytest tests -v
```

All 8 tests run locally with zero network dependencies using temporary fixtures:
- Python manifest parsing (`requirements.txt`, `pyproject.toml`) and AST inspection
- JavaScript/TypeScript parsing (`package.json`) and import scanning
- Empty and unsupported repository detection
- Missing test framework handling
- JSON schema and Markdown capsule formatting
- Execution security guardrail enforcement

---

## Evaluation Against LinkWatch

The tool was validated against the target repository [https://github.com/rishrek/LinkWatch](https://github.com/rishrek/LinkWatch):
- **Ecosystem:** `python`
- **Detected Manifests:** `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`
- **Identified Findings:**
  - `pydantic`: Manifest conflict (`requirements.txt: ==1.10.13` vs `pyproject.toml: >=2`).
  - `appdirs`: Deprecated/unmaintained since 2020 (recommends `platformdirs`).
  - `toml`: Deprecated in modern Python (Python 3.11+ standard library includes `tomllib`).
  - `click`: Loose constraint `click>=7`.
  - `six`: Python 2 compatibility shim, unpinned and unused in source code.
  - `certifi`: Undeclared import in `linkwatch/checker.py:L4`.
- **AST Usages Mapped:** Accurately linked `appdirs` to `linkwatch/cache.py:L4`, `dateutil` to `linkwatch/dates.py:L1`, and `rich`/`click` to `linkwatch/cli.py`.
- **Verification Engine:** Discovered `pytest` test suite with 4 test files.
