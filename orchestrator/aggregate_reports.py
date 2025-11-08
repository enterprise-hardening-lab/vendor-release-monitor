import json
from pathlib import Path
from datetime import datetime, timedelta, UTC
from collections import defaultdict

def collect_recent_cves(days=7):
    """Collect all CVE JSON files generated in the last N days."""
    base = Path("catalog/cves")
    Path("reports").mkdir(exist_ok=True)

    # If directory missing → create empty summary
    if not base.exists():
        print("⚠️ No CVE data directory found (catalog/cves). Creating empty summary.")
        report = {
            "week_start": (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d"),
            "week_end": datetime.now(UTC).strftime("%Y-%m-%d"),
            "vendors": {},
            "total": {},
            "generated_at": datetime.now(UTC).isoformat()
        }
        out = Path("reports/weekly_cve_summary.json")
        out.write_text(json.dumps(report, indent=2))
        print(f"✅ Created empty weekly summary at {out}")
        return report

    cutoff = datetime.now(UTC) - timedelta(days=days)
    summary = defaultdict(lambda: defaultdict(int))
    total = defaultdict(int)
    found_files = 0

    for vendor_dir in base.iterdir():
        if not vendor_dir.is_dir():
            continue
        for stream_dir in vendor_dir.iterdir():
            if not stream_dir.is_dir():
                continue
            for f in stream_dir.glob("*.json"):
                found_files += 1
                try:
                    ts = datetime.strptime(f.stem, "%Y-%m-%d")
                except Exception:
                    continue
                if ts < cutoff:
                    continue
                data = json.loads(f.read_text())
                for cve in data:
                    sev = cve.get("severity", "Unknown")
                    summary[vendor_dir.name][sev] += 1
                    total[sev] += 1

    report = {
        "week_start": (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d"),
        "week_end": datetime.now(UTC).strftime("%Y-%m-%d"),
        "vendors": summary,
        "total": total,
        "generated_at": datetime.now(UTC).isoformat()
    }

    out = Path("reports/weekly_cve_summary.json")
    out.write_text(json.dumps(report, indent=2))

    if found_files == 0:
        print("⚠️ No CVE report files found. Created empty summary.")
    else:
        print(f"✅ Aggregated {found_files} CVE report files.")
    print(f"✅ Weekly CVE summary written to {out}")
    return report


if __name__ == "__main__":
    collect_recent_cves()
