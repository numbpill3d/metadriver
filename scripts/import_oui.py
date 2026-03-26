#!/usr/bin/env python3
"""
Import IEEE OUI database into the devices table.
Downloads the official IEEE MA-L (OUI) CSV (~5MB) and bulk-inserts.

Usage:
    python3 scripts/import_oui.py --db /var/lib/wifi-logger/wifi_data.db
    python3 scripts/import_oui.py --db /var/lib/wifi-logger/wifi_data.db --file oui.csv
"""

import argparse
import csv
import io
import logging
import sqlite3
import urllib.request
from datetime import datetime
from pathlib import Path

OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


def fetch_oui_csv(url: str) -> io.StringIO:
    logger.info(f"Downloading OUI database from {url} ...")
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read().decode('utf-8', errors='replace')
    logger.info(f"Downloaded {len(data) // 1024} KB")
    return io.StringIO(data)


def import_oui(db_path: str, csv_source: io.StringIO):
    """Bulk-insert OUI records using INSERT OR REPLACE."""
    reader = csv.DictReader(csv_source)
    # IEEE CSV columns: Registry,Assignment,Organization Name,Organization Address
    now = datetime.utcnow()
    rows = []
    for row in reader:
        oui = row.get('Assignment', '').strip().upper()
        if not oui or len(oui) != 6:
            continue
        vendor = row.get('Organization Name', '').strip()
        address = row.get('Organization Address', '').strip()
        rows.append((oui, vendor, address, now))

    logger.info(f"Parsed {len(rows)} OUI entries, importing...")

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executemany(
            """INSERT OR REPLACE INTO devices (oui, vendor_name, vendor_address, last_updated)
               VALUES (?, ?, ?, ?)""",
            rows
        )
        conn.commit()

    logger.info(f"Imported {len(rows)} OUI entries into {db_path}")


def main():
    parser = argparse.ArgumentParser(description="Import IEEE OUI database")
    parser.add_argument('--db', required=True, help='Path to wifi_data.db')
    parser.add_argument('--file', help='Local OUI CSV file (skips download)')
    args = parser.parse_args()

    if not Path(args.db).exists():
        logger.error(f"Database not found: {args.db}")
        raise SystemExit(1)

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
            source = io.StringIO(f.read())
    else:
        source = fetch_oui_csv(OUI_CSV_URL)

    import_oui(args.db, source)


if __name__ == '__main__':
    main()
