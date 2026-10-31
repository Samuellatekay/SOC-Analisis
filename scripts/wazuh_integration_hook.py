#!/usr/bin/env python3
"""
Wazuh Custom Integration Script for SOC Analisis Engine.
Place this script in Wazuh Manager at:
    /var/ossec/integrations/custom-soc
Set permissions:
    chmod 750 /var/ossec/integrations/custom-soc
    chown root:wazuh /var/ossec/integrations/custom-soc
"""

import sys
import json
import urllib.request
import urllib.error

# Arguments passed by Wazuh:
# sys.argv[1] = Alert file path (temporary file containing JSON alert)
# sys.argv[2] = User / API Key (optional)
# sys.argv[3] = Hook URL (configured in ossec.conf)

if len(sys.argv) < 4:
    sys.exit(1)

alert_file_path = sys.argv[1]
api_key = sys.argv[2]
hook_url = sys.argv[3]

# 1. Read Wazuh alert JSON
try:
    with open(alert_file_path, "r", encoding="utf-8") as f:
        alert_json = json.load(f)
except Exception as e:
    sys.exit(1)

# 2. Send HTTP POST to SOC Analisis Engine
try:
    data = json.dumps(alert_json).encode("utf-8")
    req = urllib.request.Request(
        hook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Wazuh-Integration/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        pass
except Exception as e:
    sys.exit(1)

sys.exit(0)
