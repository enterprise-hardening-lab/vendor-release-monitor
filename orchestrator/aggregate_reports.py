import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

def collect_recent_cves(days=7):
    """Collect all CVE JSON files generated in the last N days."""
    base = Path("catalog/cves")
    cutoff = datetime.utcnow() - timedelta(days=days)
    summary = defaultdict(lambda: defaultdict(int))
    total = defaultdict(int)

    for vendor_dir in base.iterdir():
        if not vendor_dir.is_dir():
            continue
        for stream_dir in vendor_dir.iterdir():
            if not stream_dir.is_dir():
                continue
            for f in stream_dir.glob("*.json"):
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

    week_start = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    week_end = datetime.utcnow().strftime("%Y-%m-%d")

    report = {
        "week_start": week_start,
        "week_end": week_end,
        "vendors": summary,
        "total": total,
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

    Path("reports").mkdir(exist_ok=True)
    out = Path("reports/weekly_cve_summary.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"✅ Weekly CVE summary written to {out}")
    return report


if __name__ == "__main__":
    collect_recent_cves()
