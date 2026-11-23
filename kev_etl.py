import argparse
import json
import sqlite3
from datetime import datetime, timezone, timedelta
import pandas as pd
import requests
import os

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DB_PATH = "threat_intel.db"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "").strip()

def extract(url: str = CISA_KEV_URL) -> dict:
    """fetch raw JSON payload from the CISA KEV feed."""
    print(f"[*] Extracting data from {url} ...")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()

def transform(raw_data: dict) -> pd.DataFrame:
    """normalise, clean, and deduplicate KEV records using Pandas."""
    vulns = raw_data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError("no vulnerabilty records found in API response.")

    df = pd.DataFrame(vulns)

    column_map ={
        "cveID": "cve_id",
        "vendorProject": "vendor",
        "product": "product",
        "vulnerabilityName": "vuln_name",
        "dateAdded": "date_added",
        "shortDescription": "description",
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse": "ransomware_use",
        "notes": "notes",
    }
    df = df.rename(columns=column_map)

    expected_cols = list(column_map.values())
    for col in expected_cols:
        if col not in df.columns:
            df[col] = ""
    df = df[expected_cols].copy()

    # pandas 3.x: astype(str) preserves missing markers as NAN, so .fillna("") runs after.
    for col in expected_cols:
        df[col] = df[col].astype(str).fillna("").str.strip()

    for date_col in ("date_added", "due_date"):
        df[date_col] = pd.to_datetime(df[date_col], errors="coerce").dt.strftime("%Y-%m-%d").fillna("")

    df["ransomware_use"] = df["ransomware_use"].replace("", "Unknown")
    df = df.drop_duplicates(subset=["cve_id"], keep="last")
    df["ingested_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"[*] Transformed {len(df)} unique CVE records.")
    return df

def init_db(conn: sqlite3.Connection) -> None:
    """creates the SQLite scheme if it does not exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cisa_kev (
            cve_id          TEXT PRIMARY KEY,
            vendor          TEXT NOT NULL,
            product         TEXT NOT NULL,
            vuln_name       TEXT,
            date_added      TEXT,
            description     TEXT,
            required_action TEXT,
            due_date        TEXT,
            ransomware_use  TEXT,
            notes           TEXT,
            ingested_at     TEXT NOT NULL
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS  idx_vendor ON cisa_kev(vendor);")
    conn.execute("CREATE INDEX IF NOT EXISTS  idx_date_added ON cisa_kev(date_added);")
    conn.commit()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threatfox_iocs (
            ioc_id          TEXT PRIMARY KEY,
            ioc_value       TEXT NOT NULL,
            ioc_type        TEXT NOT NULL,
            threat_type     TEXT,
            malware         TEXT,
            confidence      TEXT,
            first_seen      TEXT,
            reporter        TEXT,
            tags            TEXT,
            ingested_at     TEXT NOT NULL
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tf_ioc_value ON threatfox_iocs(ioc_value);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tf_malware ON threatfox_iocs(malware);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tf_first_seen ON threatfox_iocs(first_seen);")

def extract_threatfox(days: int = 3, url: str = THREATFOX_API_URL) -> dict:
    """Fetch recent IOCs from ThreatFox API (days: 1 to 7)."""
    if not ABUSECH_AUTH_KEY:
        raise ValueError("ABUSECH_AUTH_KEY environment variable is not set.")
    print(f"[*] Extracting ThreatFox IOCs (last {days} days) from {url} ...")
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    resp = requests.post(url, json={"query": "get_iocs", "days": max(1, min(days, 7))}, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()

def transform_threatfox(raw_data: dict) -> pd.DataFrame:
    """Normalize and deduplicate ThreatFox IOC records using Pandas."""
    if raw_data.get("query_status") != "ok":
        raise ValueError(f"ThreatFox API returned status: {raw_data.get('query_status')}")
    iocs = raw_data.get("data") or []
    if not iocs:
        return pd.DataFrame(
            columns=[
                "ioc_id", "ioc_value", "ioc_type", "threat_type",
                "malware", "confidence", "first_seen", "reporter", "tags", "ingested_at",
            ]
        )

    df = pd.DataFrame(iocs)
    column_map = {
        "id": "ioc_id",
        "ioc": "ioc_value",
        "ioc_type": "ioc_type",
        "threat_type": "threat_type",
        "malware_printable": "malware",
        "confidence_level": "confidence",
        "first_seen_utc": "first_seen",
        "reporter": "reporter",
        "tags": "tags",
    }
    df = df.rename(columns=column_map)

    expected_cols = [
        "ioc_id", "ioc_value", "ioc_type", "threat_type",
        "malware", "confidence", "first_seen", "reporter", "tags",
    ]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = ""
    df = df[expected_cols].copy()

    for col in expected_cols:
        df[col] = df[col].apply(
            lambda v: ", ".join(str(x) for x in v) if isinstance(v, list) else ("" if v is None else str(v).strip())
        )

    df = df[df["ioc_id"] != ""].drop_duplicates(subset=["ioc_id"], keep="last")
    df["ingested_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[*] Transformed {len(df)} unique ThreatFox IOC records.")
    return df


def load_threatfox(df: pd.DataFrame, db_path: str = DB_PATH) -> None:
    """Upsert ThreatFox IOC records into threat_intel.db and report new IOCs."""
    conn = sqlite3.connect(db_path)
    try:
        init_db(conn)
        existing_ids = {
            row[0] for row in conn.execute("SELECT ioc_id FROM threatfox_iocs;").fetchall()
        }
        new_df = df[~df["ioc_id"].isin(existing_ids)]
        records = df.to_dict(orient="records")

        conn.executemany(
            """
            INSERT INTO threatfox_iocs (
                ioc_id, ioc_value, ioc_type, threat_type,
                malware, confidence, first_seen, reporter, tags, ingested_at
            ) VALUES (
                :ioc_id, :ioc_value, :ioc_type, :threat_type,
                :malware, :confidence, :first_seen, :reporter, :tags, :ingested_at
            )
            ON CONFLICT(ioc_id) DO UPDATE SET
                ioc_value   = excluded.ioc_value,
                ioc_type    = excluded.ioc_type,
                threat_type = excluded.threat_type,
                malware     = excluded.malware,
                confidence  = excluded.confidence,
                first_seen  = excluded.first_seen,
                reporter    = excluded.reporter,
                tags        = excluded.tags,
                ingested_at = excluded.ingested_at;
            """,
            records,
        )
        conn.commit()
        print(f"[+] Upserted {len(records)} ThreatFox IOCs into {db_path}.")
        print(f"[+] New IOCs added this run: {len(new_df)}")
    finally:
        conn.close()

def load(df: pd.DataFrame, db_path: str = DB_PATH) -> None:
    """Upsert cleaned records into the local SQLite database and report new CVEs."""
    conn = sqlite3.connect(db_path)
    try:
        init_db(conn)

        existing_ids = {
            row[0] for row in conn.execute("SELECT cve_id FROM cisa_kev;").fetchall()
        }
        incoming_df = df.copy()
        new_df = incoming_df[~incoming_df["cve_id"].isin(existing_ids)]

        records = incoming_df.to_dict(orient="records")
        conn.executemany(
            """
            INSERT INTO cisa_kev (
                cve_id, vendor, product, vuln_name, date_added,
                description, required_action, due_date, ransomware_use, notes, ingested_at
            ) VALUES (
                :cve_id, :vendor, :product, :vuln_name, :date_added,
                :description, :required_action, :due_date, :ransomware_use, :notes, :ingested_at
            )
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor          = excluded.vendor,
                product         = excluded.product,
                vuln_name       = excluded.vuln_name,
                date_added      = excluded.date_added,
                description     = excluded.description,
                required_action = excluded.required_action,
                due_date        = excluded.due_date,
                ransomware_use  = excluded.ransomware_use,
                notes           = excluded.notes,
                ingested_at     = excluded.ingested_at;
            """,
            records,
        )
        conn.commit()

        print(f"[+] Upserted {len(records)} total records into {db_path}.")
        print(f"[+] New CVEs added this run: {len(new_df)}")
        if not new_df.empty:
            print(new_df[["cve_id", "date_added", "vendor", "product", "ransomware_use"]].to_string(index=False))
    finally:
        conn.close()

def query_db(
    vendor: str = None,
    cve: str = None,
    ransomware_only: bool = False,
    due_within_days: int = None,
    details: bool = False,
    export_fmt: str = None,
    limit: int = 15,
    db_path: str = DB_PATH,
) -> None:
    """Run quick SOC triage queries against the local SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        clauses = []
        params = []

        if vendor:
            clauses.append("LOWER(vendor) LIKE ?")
            params.append(f"%{vendor.lower()}%")
        if cve:
            clauses.append("UPPER(cve_id) = ?")
            params.append(cve.upper())
        if ransomware_only:
            clauses.append("LOWER(ransomware_use) = 'known'")
        if due_within_days is not None:
            cutoff_date = (datetime.now(timezone.utc) + timedelta(days=due_within_days)).strftime("%Y-%m-%d")
            clauses.append("due_date != '' AND due_date <= ?")
            params.append(cutoff_date)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order_by = "due_date ASC, date_added DESC" if due_within_days is not None else "date_added DESC"
        cols = (
            "cve_id, date_added, due_date, vendor, product, vuln_name, ransomware_use, description, required_action, notes"
            if details
            else "cve_id, date_added, due_date, vendor, product, ransomware_use"
        )
        sql = f"""
            SELECT {cols}
            FROM cisa_kev
            {where_sql}
            ORDER BY {order_by}
            LIMIT ?;
        """
        params.append(limit)

        results = pd.read_sql_query(sql, conn, params=params)
        if results.empty:
            print("[-] No matching records found.")
            return

        if export_fmt == "csv":
            out_file = "kev_export.csv"
            results.to_csv(out_file, index=False)
            print(f"[+] Exported {len(results)} records to {out_file}.")
        elif export_fmt == "json":
            out_file = "kev_export.json"
            results.to_json(out_file, orient="records", indent=2)
            print(f"[+] Exported {len(results)} records to {out_file}.")        
        elif details:
            for _, row in results.iterrows():
                print("-" * 72)
                print(f"CVE:             {row['cve_id']} | Ransomware: {row['ransomware_use']}")
                print(f"Vendor/Product:  {row['vendor']} — {row['product']}")
                print(f"Name:            {row['vuln_name']}")
                print(f"Added / Due:     {row['date_added']} / {row['due_date'] or 'N/A'}")
                print(f"Description:     {row['description']}")
                print(f"Required Action: {row['required_action']}")
                if row["notes"]:
                    print(f"Notes:           {row['notes']}")
            print("-" * 72)
        else:
            print(results.to_string(index=False))
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="CISA KEV Threat Intelligence ETL Pipeline")
    parser.add_argument("--sync", action="store_true", help="run full Extract -> Transform -> Load pipeline")
    parser.add_argument("--vendor", type=str, help="Filter stored CVEs by vendor (e.g., Microsft)")
    parser.add_argument("--cve", type=str, help="Look up a specific CVE ID (e.g., CVE-2024-21413)")
    parser.add_argument("--ransomware", action="store_true", help="Show only CVEs with known ransomware use")
    parser.add_argument("--limit", type=int, default=15, help="Max rows to display (default: 15)")
    parser.add_argument("--due-days", type=int, default=None, help="Show CVEs with due_date on or before N days from today (includes overdue)")
    parser.add_argument("--details", action="store_true", help="Show full description, required action, and notes")
    parser.add_argument("--export", choices=["csv", "json"], default=None, help="Export matching results to kev_export.csv or kev_export.json",)
    parser.add_argument("--threatfox", action="store_true", help="Include ThreatFox recent IOCs on sync")
    parser.add_argument("--days", type=int, default=3, help="ThreatFox lookback window in days (1-7, default: 3)")
    args = parser.parse_args()

    if args.sync:
        raw = extract()
        df = transform(raw)
        load(df)

    if (args.vendor or args.cve or args.ransomware or args.due_days is not None or args.export is not None or not args.sync):
        query_db(
            vendor=args.vendor,
            cve=args.cve,
            ransomware_only=args.ransomware,
            due_within_days=args.due_days,
            details=args.details,
            export_fmt=args.export,
            limit=args.limit,
        )

    if args.threatfox and not ABUSECH_AUTH_KEY:
        print("[-] Skipping ThreatFox sync: ABUSECH_AUTH_KEY is not set.")
        
if __name__ == "__main__":
    main()
