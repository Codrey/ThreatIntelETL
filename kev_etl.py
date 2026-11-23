import argparse
import sqlite3
from datetime import datetime, timezone
import pandas as pd
import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DB_PATH = "threat_intel.db"


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

def load(df: pd.DataFrame, db_path: str = DB_PATH) -> None:
    """upsert cleaned records into the local SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        init_db(conn)
        records = df.to_dict(orient="records")
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
        print(f"[+] Load {len(records)} records into {db_path}.")
    finally:
        conn.close()

def query_db(vendor: str = None, cve: str = None, ransomware_only: bool = False, limit: int = 15) -> None:
    """run quick SOC triage queries against the local SQLite database."""
    conn = sqlite3.connect(DB_PATH)
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

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT cve_id, date_added, vendor, product, ransomware_use
            FROM cisa_kev
            {where_sql}
            ORDER BY date_added DESC
            LIMIT ?;
        """

        params.append(limit)

        results = pd.read_sql_query(sql, conn, params=params)
        if results.empty:
            print("[-] No matching records found.")
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
    args = parser.parse_args()

    if args.sync:
        raw = extract()
        df = transform(raw)
        load(df)

    if args.vendor or args.cve or args.ransomware or not args.sync:
        query_db(vendor=args.vendor, cve=args.cve, ransomware_only=args.ransomware, limit=args.limit)

if __name__ == "__main__":
    main()
