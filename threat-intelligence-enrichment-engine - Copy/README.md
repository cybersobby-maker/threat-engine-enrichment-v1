# Threat Intelligence Enrichment Engine

A threat-intelligence workbench built with Python, Streamlit, and SQLite. It normalizes indicators of compromise (IOCs), adds explainable local analysis, optionally retrieves read-only reputation data from VirusTotal and AbuseIPDB, produces a transparent investigation-priority score, and preserves evidence in a local history.

> **Safe-by-default:** external lookups are off unless explicitly enabled. The application does not visit submitted URLs, download files, execute samples, scan hosts, or block traffic. Only use external lookup for indicators you are authorized to share with those providers.

## What it demonstrates

- IOC parsing and normalization: IPv4/IPv6, domains, HTTP(S) URLs, MD5, SHA-1, and SHA-256.
- Common defanging cleanup such as `hxxps://login[.]example` → `https://login.example`.
- Passive threat-intelligence enrichment using documented read-only API endpoints.
- Explainable risk scoring with evidence and provider attribution instead of a black-box verdict.
- Streamlit dashboard with KPI cards, risk/type charts, findings, filters, detailed evidence, CSV export, and enrichment history.
- SQLite persistence, CSV/TXT batch input, companion CLI, environment-based secret handling, and unit tests.
- Public/reserved IP guardrails that skip external lookup for non-global IPs.

## Architecture

```text
                 ┌─────────────────────────┐
                 │ Streamlit UI / CLI      │
                 └────────────┬────────────┘
                              │
                   ┌──────────▼──────────┐
                   │ Normalizer / Parser │
                   └──────────┬──────────┘
                              │
                 ┌────────────▼────────────┐
                 │ Local Heuristic Analysis│
                 └────────────┬────────────┘
                              │
                External lookup OFF by default
                    ┌─────────┴─────────┐
                    │                   │
            ┌───────▼──────┐   ┌────────▼───────┐
            │ VirusTotal v3│   │ AbuseIPDB v2   │
            └───────┬──────┘   └────────┬───────┘
                    └──────────┬────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Scoring + Evidence  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Local SQLite History│
                    └─────────────────────┘
```

## Windows + VS Code setup

Open PowerShell in VS Code's integrated terminal, then run:

```powershell
# 1. Move into the project directory
cd path\to\threat-intelligence-enrichment-engine

# 2. Create and activate a project-specific virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# If PowerShell blocks activation, use Command Prompt instead:
# .venv\Scripts\activate.bat

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Start the dashboard
python -m streamlit run app.py
```

Streamlit opens a local web page, usually at `http://localhost:8501`. To stop it, press `Ctrl+C` in the terminal.

If `py -3.11` does not work, install a supported Python version and confirm `py --version` or `python --version` works. In VS Code, use **Python: Select Interpreter** and choose the `.venv` interpreter created inside this project.

### Run the automated tests

```powershell
python -m pytest -q
```

### Use the command line

The CLI is included for automation and scripting. It uses local-only analysis by default:

```powershell
# Single IOC
python cli.py 8.8.8.8

# Multiple IOCs (quote URLs so PowerShell treats them as one argument)
python cli.py 8.8.8.8 example.com "https://example.com/login"

# Enrich a CSV or plain-text list
python cli.py --file sample_iocs.csv --output results.csv

# Return machine-readable JSON
python cli.py --file sample_iocs.csv --json
```

External providers are only queried when explicitly requested with `--external` (CLI) or when the toggle is enabled in the dashboard:

```powershell
python cli.py 8.8.8.8 --external
```

Provider keys must be configured first. VirusTotal's public API can be rate-limited; this dashboard conservatively processes at most four indicators per run when a VirusTotal key and external lookups are enabled.

## Optional API keys

1. Copy the example environment file:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Add your own keys to `.env`:
   ```dotenv
   VIRUSTOTAL_API_KEY=your_virustotal_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   ```
3. Restart Streamlit or rerun the CLI.

Get keys from the provider accounts you control:

- [VirusTotal API documentation](https://docs.virustotal.com/reference/overview)
- [AbuseIPDB API v2 documentation](https://docs.abuseipdb.com/)

`.env` is ignored by Git. Never put API keys directly into Python files, screenshots, commits, or public repositories. You can run and demonstrate the project without either key.

## How to use the dashboard

1. Open **Enrich indicators**.
2. Paste an IOC per line, or upload a CSV. The app looks for a column named `indicator`, `ioc`, `value`, `observable`, `ip`, `domain`, `url`, or `hash`; otherwise, it uses the first column.
3. Leave external lookups off for a local-only demonstration. Enable the sidebar toggle only after reviewing the data-sharing implications and configuring your keys.
4. Select **Run enrichment** to view the score, evidence, provider response, and exportable CSV.
5. Use **Overview** for current unique indicators and risk charts, and **History** to filter prior runs.

`sample_iocs.csv` uses reserved example domains, documentation IPs, and a synthetic hash-shaped string. They are for demonstrating parser/heuristic behavior and should not be described as confirmed malicious IOCs.

## Risk scoring model

The score is an **investigation-priority aid**, not a probability of compromise and not proof of maliciousness:

- **0 — Unknown:** insufficient positive evidence; never interpret as “safe”.
- **1–24 — Low**
- **25–49 — Medium**
- **50–74 — High**
- **75–100 — Critical**

Local heuristics produce explainable, low-confidence signals and are capped at 45 so local-only heuristics cannot independently label an IOC High or Critical. When available, VirusTotal malicious/suspicious detections and AbuseIPDB's abuse confidence score can raise the risk score. Two independent providers giving positive abuse signals add a small corroboration adjustment. Every triggered signal is recorded as evidence.

This model is intentionally simple enough to explain in an interview. In a future iteration, calibrate thresholds against a labeled dataset, track false positives/negatives, and version the scoring model.

## Data handling and limitations

- Input normalization and local heuristics are performed on your machine.
- When external lookup is enabled, selected IOC values are sent to the configured provider APIs. Even a domain or URL can be sensitive; follow your employer/lab's data-handling requirements.
- Non-global IP addresses are not sent to either provider.
- Provider responses can be incomplete, stale, unavailable, or limited by account quota. The app reports lookup errors separately from a clean report.
- Some local heuristics can flag legitimate activity. TLD choice, hyphens, HTTP, and words like `login` are weak signals, not verdicts.
- The project does not include automated blocking, endpoint scanning, URL browsing, sample downloading, file detonation, authentication, multi-user access control, or production monitoring.

## Suggested resume entry

**Threat Intelligence Enrichment Engine | Python, Streamlit, SQLite, REST APIs**

- Built an IOC enrichment workbench that normalizes IPs, domains, URLs, and file hashes, with optional VirusTotal and AbuseIPDB reputation checks.
- Implemented explainable scoring, evidence attribution, non-global IP guardrails, CSV batch processing, and persistent SQLite investigation history.
- Developed an interactive SOC-style dashboard and companion CLI, with unit tests and safe-by-default external lookup controls.

Only include the components you have personally run, tested, and can explain. A strong project walkthrough should cover one normalizer case, one API response, how the score was calculated, how you handled errors, and a false-positive limitation.

## Next enhancements

- Add STIX/TAXII feed ingestion and mapping to a normalized internal IOC schema.
- Add MITRE ATT&CK references when a source provides grounded technique information.
- Add analyst notes, case IDs, and a timeline of score changes.
- Add caching and provider-specific quota tracking.
- Add type-checking/linting in CI and integration tests using mocked HTTP responses.

## License

MIT — see `LICENSE`.

Important about your sample file

Your sample_iocs.csv contains reserved example domains and documentation IP addresses. Those values are intended for local testing, and your code deliberately skips external lookups for non-global IP addresses.

Use a public IP like 8.8.8.8 for the first external test instead.