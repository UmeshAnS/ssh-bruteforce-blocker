import os
import re
import json
import time
import argparse
import subprocess
from datetime import datetime, timezone
from collections import defaultdict
import requests

# Regex matching standard OpenSSH failed password / invalid user log lines
FAILED_SSH_REGEX = re.compile(
    r"(?:Failed password|Invalid user).*from (\d{1,3}(?:\.\d{1,3}){3})"
)

WHITELIST_IPS = {"127.0.0.1", "::1"}


def check_abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "Skipped (No ABUSEIPDB_API_KEY)"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json()["data"]
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "total_reports": data.get("totalReports", 0),
            }
        return {"status": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": f"Error: {e}"}


def block_ip(ip: str, dry_run: bool) -> str:
    cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]
    if dry_run:
        return f"[DRY-RUN] Would execute: {' '.join(cmd)}"

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return f"[ACTIVE] Blocked {ip} via UFW firewall"
    except Exception as e:
        return f"[ERROR] Failed to block {ip}: {e}"


def log_alert(alert_file: str, alert_data: dict):
    with open(alert_file, "a") as f:
        f.write(json.dumps(alert_data) + "\n")


def process_log_stream(lines, threshold: int, dry_run: bool, alert_file: str, api_key: str):
    failed_attempts = defaultdict(int)
    blocked_ips = set()

    for line in lines:
        match = FAILED_SSH_REGEX.search(line)
        if not match:
            continue

        ip = match.group(1)
        if ip in WHITELIST_IPS or ip in blocked_ips:
            continue

        failed_attempts[ip] += 1
        print(f"[!] Failed SSH attempt #{failed_attempts[ip]} from {ip}")

        if failed_attempts[ip] >= threshold:
            print(f"[*] Threshold ({threshold}) reached for {ip}. Querying threat intel...")
            intel = check_abuseipdb(ip, api_key)
            action_result = block_ip(ip, dry_run)
            blocked_ips.add(ip)

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "SSH_BRUTE_FORCE_DETECTED",
                "source_ip": ip,
                "failed_attempts": failed_attempts[ip],
                "threat_intel": intel,
                "mitigation": action_result,
            }
            log_alert(alert_file, alert)

            print("=" * 65)
            print(f"ALERT: Brute-force threshold exceeded by {ip}")
            print(f"Threat Intel: {json.dumps(intel)}")
            print(f"Mitigation:   {action_result}")
            print("=" * 65)


def tail_file(filepath: str):
    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line


def main():
    parser = argparse.ArgumentParser(
        description="Automated SSH Brute-Force Detector & Firewall Blocker"
    )
    parser.add_argument(
        "-f", "--file", default="/var/log/auth.log", help="Path to SSH auth log (default: /var/log/auth.log)"
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=5, help="Failed attempts before blocking (default: 5)"
    )
    parser.add_argument(
        "--batch", action="store_true", help="Parse an existing log file from start to finish instead of tailing"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate firewall blocks without modifying UFW rules"
    )
    parser.add_argument(
        "-o", "--alerts", default="alerts.jsonl", help="Output JSONL file for security alerts"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] Log file not found: {args.file}")
        return

    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    mode = "DRY-RUN SIMULATION" if args.dry_run else "ACTIVE ENFORCEMENT"
    print(f"[*] Starting SSH Defender [{mode}] on {args.file} (Threshold: {args.threshold})")

    if args.batch:
        with open(args.file, "r") as f:
            process_log_stream(f, args.threshold, args.dry_run, args.alerts, api_key)
    else:
        try:
            process_log_stream(tail_file(args.file), args.threshold, args.dry_run, args.alerts, api_key)
        except KeyboardInterrupt:
            print("\n[*] Stopping SSH Defender.")


if __name__ == "__main__":
    main()
