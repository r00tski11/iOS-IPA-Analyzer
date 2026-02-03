# iOS IPA Analyzer

Static security scanner for iOS IPA's. Detects hardcoded secrets, weak cryptography, binary vulnerabilities, and misconfigurations in `.ipa` files and `.xcarchive` builds.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Tests](https://img.shields.io/badge/Tests-204%20passing-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## The Problem

iOS applications frequently ship with:
- Hardcoded API keys and credentials
- Weak or deprecated cryptographic implementations
- Missing binary protections (PIE, stack canaries)
- Misconfigured App Transport Security
- Sensitive data in provisioning profiles

Most static analysis tools flag too many false positives - every base64 string gets flagged as a "potential secret." This makes triage tedious.

---

## How it works

- Uses Shannon entropy analysis + context keywords to filter out noise (only flags high-entropy strings near things like `api_key` or `secret`)
- Parses Mach-O headers directly with macholib instead of grepping for strings
- 134 rules based on HackTricks iOS checklist and bug bounty patterns
- Outputs SARIF for GitHub Security tab integration

---

## Quick Start

```bash
# Install
git clone https://github.com/r00tski11/iOS-IPA-Analyzer.git
cd iOS-IPA-Analyzer
pip install -e .

# Scan an IPA
ipa-analyzer scan app.ipa

# Scan with full ruleset
ipa-analyzer scan app.ipa -r rules/ios_security.yaml -r rules/ios_bugbounty.yaml

# Generate HTML report
ipa-analyzer scan app.ipa -f html -o report.html
```

---

## Features

| Capability | Details |
|------------|---------|
| **8 Specialized Detectors** | Secrets, Binary Protections, ATS, Crypto, Entitlements, Privacy, URLs, Deprecated APIs |
| **134 Security Rules** | Based on real bug bounty findings and OWASP Mobile Top 10 |
| **5 Output Formats** | Console, JSON, HTML, SARIF, PDF |
| **CI/CD Integration** | SARIF format for GitHub Security tab, `--fail-on` flag for build gates |
| **xcarchive Support** | Scan Xcode build archives directly without IPA conversion |
| **Low False Positives** | Entropy + context matching vs naive string grep |

### Detectors

| Detector | What It Finds |
|----------|---------------|
| `secrets` | AWS keys, Google API keys, GitHub tokens, JWTs, private keys, high-entropy strings |
| `binary_protections` | Missing PIE, stack canaries, ARC, heap execution flags (Mach-O parsing) |
| `ats` | NSAllowsArbitraryLoads, exception domains, insecure HTTP |
| `crypto` | MD5/SHA1 usage, DES/3DES/RC4, ECB mode, hardcoded keys |
| `entitlements` | get-task-allow, wildcard keychain access, sensitive entitlements |
| `privacy` | Missing PrivacyInfo.xcprivacy manifest, empty usage descriptions |
| `url_endpoints` | HTTP URLs, staging/dev endpoints, private IPs, localhost |
| `deprecated_apis` | strcpy, gets, sprintf, UIWebView, weak RNG |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.9+ |
| CLI Framework | Click |
| Binary Parsing | macholib (Mach-O headers) |
| Terminal UI | Rich (colors, tables, progress) |
| Templating | Jinja2 (HTML reports) |
| PDF Generation | fpdf2 |
| Rules Engine | PyYAML |

---

## Installation

```bash
# Clone repository
git clone https://github.com/r00tski11/iOS-IPA-Analyzer.git
cd iOS-IPA-Analyzer

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

---

## Usage Examples

```bash
# Basic scan with console output
ipa-analyzer scan app.ipa

# Verbose output with remediation details
ipa-analyzer scan app.ipa -v

# JSON output for programmatic processing
ipa-analyzer scan app.ipa -f json -o results.json

# HTML report for sharing
ipa-analyzer scan app.ipa -f html -o report.html

# PDF for formal deliverables
ipa-analyzer scan app.ipa -f pdf -o report.pdf

# SARIF for GitHub Security integration
ipa-analyzer scan app.ipa -f sarif -o results.sarif

# CI/CD: fail build on high+ severity findings
ipa-analyzer scan app.ipa --fail-on high -f sarif -o results.sarif

# Stack multiple rule files
ipa-analyzer scan app.ipa \
  -r rules/ios_security.yaml \
  -r rules/ios_bugbounty.yaml

# Run specific detectors only
ipa-analyzer scan app.ipa -c secrets,binary_protections,ats

# Scan xcarchive directly (no IPA conversion needed)
ipa-analyzer scan MyApp.xcarchive
```

---

## Testing

The project includes 204 tests covering detectors, reporters, rule loading, and edge cases.

```bash
# Run full test suite
pytest -v

# Run with coverage
pytest --cov=ipa_analyzer --cov-report=term-missing

# Run specific test file
pytest tests/test_secrets_detector.py -v
```

---

## Project Structure

```
iOS-IPA-Analyzer/
├── src/ipa_analyzer/
│   ├── cli.py                 # Click CLI entry point
│   ├── core/
│   │   ├── context.py         # AnalysisContext dataclass
│   │   ├── extractor.py       # IPA + xcarchive extraction
│   │   └── scanner.py         # Orchestration pipeline
│   ├── detectors/             # 8 security detectors
│   ├── reporters/             # 5 output formats
│   └── utils/                 # Entropy, scoring, rules engine
├── rules/
│   ├── ios_security.yaml      # security rules
│   └── ios_bugbounty.yaml     # bug bounty rules
├── tests/                     # tests
└── pyproject.toml
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
