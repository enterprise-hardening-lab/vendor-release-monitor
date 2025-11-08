# 🧩 Vendor Release & CVE Monitoring Orchestrator

## 🎯 Overview
This repository automates **vendor release detection**, **CVE ingestion**, and **weekly compliance reporting** for multiple OS vendors:
- Ubuntu
- Red Hat Enterprise Linux (RHEL)
- Amazon Linux

It integrates with **OpenSearch** for analytics and **GitHub Issues** for visibility.

---

## 🧱 Architecture Overview

.github/workflows/
├── vendor-cve-monitor.yml # Fetches CVEs per vendor & creates issues
├── vendor-cve-summary.yml # Aggregates weekly summary & pushes to OpenSearch
└── vendor-release-controller.yml # Detects new OS releases

connectors/ # Vendor-specific release + CVE collectors
orchestrator/ # Enrichment, aggregation, and reporting logic
catalog/state/ # Stores last known vendor versions
reports/ # Stores weekly summaries


---

## ⚙️ Automation Flow
1. **Vendor Release Monitor**
   - Detects new OS releases
   - Updates state and triggers downstream pipelines

2. **CVE Monitor (Weekly or On-Demand)**
   - Fetches vendor CVEs
   - Validates JSON schema
   - Creates GitHub Issues for each new CVE

3. **Weekly Summary**
   - Aggregates vendor reports → `reports/weekly_cve_summary.json`
   - Pushes summary to OpenSearch for dashboards
   - Creates a “📊 Weekly CVE Summary” GitHub Issue

---

## 🔒 Secrets Required

| Secret | Description |
|--------|-------------|
| `OPENSEARCH_URL` | OpenSearch endpoint |
| `OPENSEARCH_USER` | Auth username |
| `OPENSEARCH_PASS` | Auth password |
| `OPENSEARCH_INDEX` | Target index (e.g., `vendor-cve-summary`) |

---

## 🧩 GitHub Workflows

| Workflow | Description | Trigger |
|-----------|--------------|----------|
| `vendor-release-controller.yml` | Detects vendor OS releases | Manual |
| `vendor-cve-monitor.yml` | Fetches CVEs & creates GitHub Issues | Manual / Weekly |
| `vendor-cve-summary.yml` | Aggregates CVE reports & updates OpenSearch | Weekly (cron) |

---

## 📊 OpenSearch Dashboard
- Index Pattern: `vendor-cve-summary*`
- Time Field: `generated_at`

Visualizations:
1. CVE Trend per Vendor (Line)
2. Severity Distribution (Stacked Bar)
3. Vendor Split (Pie)
4. Total Critical CVEs (Metric)

---

## 🛠️ Example Outputs
```json
{
  "week_start": "2025-11-01",
  "week_end": "2025-11-08",
  "vendors": {
    "ubuntu": {"Critical": 2, "High": 4},
    "rhel": {"Critical": 1, "High": 3}
  },
  "total": {"Critical": 3, "High": 7}
}
