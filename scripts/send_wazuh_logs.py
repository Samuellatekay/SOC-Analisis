"""
Wazuh Log Ingestion Client.
Sends Wazuh alert records (JSON or alerts.json lines) to the SOC Analisis Engine.

Usage:
    # 1. Send sample alerts
    python scripts/send_wazuh_logs.py --file sample_data/wazuh_sample.json

    # 2. Send custom alerts.json from Wazuh server
    python scripts/send_wazuh_logs.py --file /var/ossec/logs/alerts/alerts.json --url http://127.0.0.1:8000/api/v1/alerts/ingest/wazuh
"""

import argparse
import json
import sys
import requests


def send_wazuh_logs(file_path: str, api_url: str):
    print(f"[*] Reading Wazuh alerts from: {file_path}")
    print(f"[*] Target SOC API: {api_url}")

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    payload = []
    # Check if standard JSON array
    if content.startswith("["):
        payload = json.loads(content)
    else:
        # JSON Lines (alerts.json format from /var/ossec/logs/alerts/)
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    print(f"[*] Parsed {len(payload)} Wazuh alert(s). Forwarding to SOC Engine...")

    try:
        response = requests.post(api_url, json=payload, timeout=10.0)
        if response.status_code == 200:
            results = response.json()
            print(f"[+] Successfully processed {len(results)} alert(s)!")
            for r in results:
                print(
                    f"    - Event ID: {r['event_id'][:8]}... | "
                    f"Type: {r['alert_type'][:35]:<35} | "
                    f"AHP Risk: {r['risk_score']:>5.1f} | "
                    f"Level: {r['risk_level'].upper():<6} | "
                    f"Filtered: {r['filtered_as_noise']}"
                )
        else:
            print(f"[-] Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest Wazuh alerts into SOC Analisis Engine")
    parser.add_argument(
        "--file",
        default="sample_data/wazuh_sample.json",
        help="Path to Wazuh alerts JSON or alerts.json file",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/api/v1/alerts/ingest/wazuh",
        help="SOC API Wazuh Ingest Endpoint",
    )

    args = parser.parse_args()
    send_wazuh_logs(args.file, args.url)
