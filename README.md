# ThreatIntelETL

A local SQLite based Threat Intelligence ETL and SOC analyst triage pipeline (`kev_etl.py`) built with Python. Ingesting the **CISA Known Exploited Vulnerabilities (KEV)** catalog and optionally enriches the `threat_intel.db` with any recent Indicators of Compromise (IOCs) from **abuse.ch ThreatFox**.

---

## Features

- **Automated ETL Pipeline (`--sync`)**: Extracts, normalizes, deduplicates, and upserts vulnerability records into a local SQLite database (`threat_intel.db`), reporting newly added CVEs on each run.
- **Multi-Feed Enrichment (`--threatfox`)**: Optionally ingests recent IOCs (IPs, domains, URLs, file hashes, and malware family metadata) from abuse.ch ThreatFox into a dedicated `threatfox_iocs` table.
- **Fast Local SOC Triage**: Filter stored vulnerabilities by vendor, specific CVE ID, known ransomware usage, or upcoming/overdue remediation deadlines (`--due-days`).
- **Detailed Remediation View (`--details`)**: Inspect full vulnerability descriptions, CISA required actions, and notes directly in the terminal.
- **Portable Reporting (`--export`)**: Export any filtered triage query to `kev_export.csv` or `kev_export.json`.

---

## Prerequisites

- **Python**: 3.10+
- **Dependencies**:
  - `pandas`
  - `requests`

---

## Installation

1. Clone or navigate to the project directory:
   ```bash
   cd ~/projects/ThreatIntelETL
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install required packages:
   ```bash
   pip install pandas requests
   ```

---

## Configuration & Threat Feeds

### 1. CISA Known Exploited Vulnerabilities (KEV)
- **Authentication**: None required (public JSON feed).
- **Target Table**: `cisa_kev`

### 2. ThreatFox (abuse.ch) — Optional Second Feed
ThreatFox requires a free abuse.ch `Auth-Key` supplied via the `ABUSECH_AUTH_KEY` environment variable:

1. Register or log in at the [abuse.ch Authentication Portal](https://auth.abuse.ch/) and generate an `Auth-Key`.
2. Export the key in your terminal session before running a sync:
   ```bash
   export ABUSECH_AUTH_KEY="your_auth_key_here"
   ```

> **Note:** If `ABUSECH_AUTH_KEY` is not set, `--sync` will still update `cisa_kev` normally and gracefully skip ThreatFox ingestion.

---

## Usage

### Sync Threat Feeds

Sync the CISA KEV catalog:
```bash
python3 kev_etl.py --sync
```

Sync both CISA KEV and the last 3 days of ThreatFox IOCs (1–7 days supported):
```bash
export ABUSECH_AUTH_KEY="your_auth_key_here"
python3 kev_etl.py --sync --threatfox --days 3
```

### Query & Triage Stored CVEs

Show the 15 most recently added KEV entries (default query behavior):
```bash
python3 kev_etl.py
```

Filter by vendor and known ransomware campaign usage:
```bash
python3 kev_etl.py --vendor Microsoft --ransomware
```

Look up a specific CVE with full description and required action:
```bash
python3 kev_etl.py --cve CVE-2024-21413 --details
```

Find CVEs due within the next 7 days (including overdue items) linked to ransomware:
```bash
python3 kev_etl.py --due-days 7 --ransomware
```

### Export Triage Results

Export matching records to CSV or JSON:
```bash
python3 kev_etl.py --vendor Microsoft --ransomware --export csv
python3 kev_etl.py --due-days 14 --limit 25 --export json
```

---

## CLI Reference

| Flag | Description |
| :--- | :--- |
| `--sync` | Run the Extract -> Transform -> Load pipeline against the CISA KEV feed. |
| `--threatfox` | Include ThreatFox recent IOCs during `--sync` (requires `ABUSECH_AUTH_KEY`). |
| `--days N` | Lookback window in days (`1`–`7`, default: `3`) for ThreatFox IOC ingestion. |
| `--vendor TEXT` | Case-insensitive substring filter on the vendor column (e.g., `Microsoft`). |
| `--cve CVE-ID` | Look up an exact CVE identifier (e.g., `CVE-2024-21413`). |
| `--ransomware` | Filter to vulnerabilities where `ransomware_use` is `Known`. |
| `--due-days N` | Show CVEs with a `due_date` on or before `N` days from today (sorted by deadline). |
| `--details` | Print full vulnerability names, descriptions, required actions, and notes. |
| `--export {csv,json}` | Write query results to `kev_export.csv` or `kev_export.json`. |
| `--limit N` | Maximum number of records to display or export (default: `15`). |

---

## Database Schema (`threat_intel.db`)

- **`cisa_kev`**: Keyed by `cve_id`, storing `vendor`, `product`, `vuln_name`, `date_added`, `due_date`, `ransomware_use`, `description`, `required_action`, `notes`, and `ingested_at`.
- **`threatfox_iocs`**: Keyed by `ioc_id`, storing `ioc_value`, `ioc_type`, `threat_type`, `malware`, `confidence`, `first_seen`, `reporter`, `tags`, and `ingested_at`.

## Reference Material

In support data wrangling and the transformation concepts used within this pipeline and project see docs and reference below:

* **Data Analysis with Python (NumPy, Matplotlib, and Pandas)** by Bernd Klein `python-course.eu`
  * **Relevant concepts applied in `kev_etl.py`:** Pandas `DataFrame` construction, column mapping, normalization, handling missing/`NaN` values, deduplication and exporting the structured data to CSV and JSON.