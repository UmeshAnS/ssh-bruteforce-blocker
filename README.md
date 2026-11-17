# Automated SSH Brute-Force Detector & Firewall Blocker

A lightweight Blue Team / SOC intrusion prevention daemon built in Python that monitors Linux authentication logs (`auth.log`) for SSH brute-force activity, enriches attacker IPs via the **AbuseIPDB v2 REST API**, logs structured JSONL security alerts, and automatically blocks malicious IPs via `ufw` firewall rules.

## Features
- **Real-Time & Batch Log Monitoring:** Tails `/var/log/auth.log` continuously or audits historical log files in `--batch` mode.
- **Threat Intelligence Enrichment:** Queries the AbuseIPDB v2 API to fetch attacker confidence scores, ISP, country, and report counts prior to mitigation.
- **Automated Active Defense & Dry-Run Mode:** Injects high-priority `ufw` deny rules once a configurable failure threshold is breached, with `--dry-run` support for safe lab simulation.
- **SIEM-Ready JSONL Alerting:** Writes structured JSON alerts to `alerts.jsonl` for ingestion into Splunk or ELK.

## Usage
```bash
# Safe dry-run simulation against a sample log
python ssh_defender.py -f sample_auth.log -t 5 --batch --dry-run

# Live real-time protection on Linux (requires sudo for UFW)
export ABUSEIPDB_API_KEY="your_api_key"
sudo -E python3 ssh_defender.py -f /var/log/auth.log -t 5

[*] Starting SSH Defender [DRY-RUN SIMULATION] on sample_auth.log (Threshold: 5)
[!] Failed SSH attempt #1 from 203.0.113.45
[!] Failed SSH attempt #2 from 203.0.113.45
[!] Failed SSH attempt #3 from 203.0.113.45
[!] Failed SSH attempt #4 from 203.0.113.45
[!] Failed SSH attempt #5 from 203.0.113.45
[*] Threshold (5) reached for 203.0.113.45. Querying threat intel...
=================================================================
ALERT: Brute-force threshold exceeded by 203.0.113.45
Threat Intel: {"abuse_confidence_score": 0, "country": null, "isp": null, "total_reports": 7}
Mitigation:   [DRY-RUN] Would execute: sudo ufw insert 1 deny from 203.0.113.45 to any
=================================================================
[!] Failed SSH attempt #1 from 198.51.100.88
