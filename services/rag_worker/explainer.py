"""
Asynchronous RAG & External LLM Explainer for SOC Alerts.
Retrieves graph context (ATT&CK techniques, vulnerability CVEs, asset context)
and generates analyst triage summaries and recommended actions using an External AI/LLM API
(OpenAI, Azure, Groq, External Ollama, vLLM) with deterministic expert fallback.
"""

from typing import Dict, Any, List, Optional
import os
import requests


class RAGExplainer:
    def __init__(
        self,
        provider: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: float = 3.0,
    ):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.api_base = api_base or os.getenv("LLM_API_BASE", "https://api.openai.com/v1")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        self.model_name = model_name or os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.timeout = timeout
        
        # Check if enabled
        enabled_val = os.getenv("LLM_ENABLED", os.getenv("OLLAMA_ENABLED", "false")).lower()
        self.enabled = enabled_val in ("true", "1", "yes")

        # ATT&CK technique mapping dictionary for offline / fast path
        self.attack_db = {
            "ssh_brute_force": {
                "id": "T1110.001",
                "name": "Brute Force: Password Guessing",
                "tactics": ["Credential Access"],
                "mitigations": [
                    "Block attacking source IP at perimeter firewall",
                    "Enforce SSH key-based authentication and disable password login",
                    "Implement fail2ban or aggressive rate-limiting on port 22",
                    "Audit affected user accounts for suspicious active sessions",
                ],
            },
            "port_scan": {
                "id": "T1046",
                "name": "Network Service Discovery",
                "tactics": ["Discovery"],
                "mitigations": [
                    "Filter unsolicited probe packets at ingress ACLs",
                    "Inspect firewall drop logs for source reconnaissance patterns",
                    "Ensure exposed services do not reveal sensitive server headers",
                ],
            },
            "web_attack": {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": ["Initial Access"],
                "mitigations": [
                    "Deploy/update WAF virtual patch rules for identified injection payloads",
                    "Verify backend database parameterization",
                    "Review application logs for error codes (500/SQL syntax errors) from target IP",
                ],
            },
            "malware_communication": {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols (C2)",
                "tactics": ["Command and Control"],
                "mitigations": [
                    "Sinkhole or block C2 destination IP/domain in DNS & proxy",
                    "Isolate infected host workstation/server from corporate VLAN immediately",
                    "Trigger forensic memory and disk triage on endpoint via EDR agent",
                ],
            },
            "ransomware": {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactics": ["Impact"],
                "mitigations": [
                    "IMMEDIATE ACTION: Isolate host network interface to prevent lateral spread",
                    "Terminate suspicious encryption processes and review volume shadow copies",
                    "Identify patient zero via authentication and lateral movement audit logs",
                ],
            },
        }

    def retrieve_graph_context(self, alert_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        norm_type = alert_type.lower().replace(" ", "_")
        matched_info = None
        for k, info in self.attack_db.items():
            if k in norm_type:
                matched_info = info
                break

        if not matched_info:
            matched_info = {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactics": ["Execution"],
                "mitigations": [
                    "Inspect command line executions on target host",
                    "Validate process hierarchy and parent process anomalies",
                ],
            }

        return {
            "technique_id": matched_info["id"],
            "technique_name": matched_info["name"],
            "tactics": matched_info["tactics"],
            "mitigations": matched_info["mitigations"],
            "cve": context.get("cve_id", "N/A"),
            "target_criticality": context.get("asset_business_value", "support"),
        }

    def generate_explanation(
        self,
        alert_dict: Dict[str, Any],
        ahp_result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generates contextual RAG analysis for the analyst using External AI / LLM.
        Tries external LLM if enabled; otherwise falls back gracefully to deterministic expert synthesis.
        """
        graph_ctx = self.retrieve_graph_context(alert_dict.get("alert_type", ""), context)
        
        explanation_text = None

        if self.enabled:
            prompt = (
                f"You are a Tier-3 SOC Analyst Assistant. Analyze this alert:\n"
                f"- Event ID: {alert_dict.get('event_id')}\n"
                f"- Type: {alert_dict.get('alert_type')}\n"
                f"- Source IP: {alert_dict.get('src_ip')} -> Destination: {alert_dict.get('dst_ip')}\n"
                f"- AHP Risk Score: {ahp_result.get('final_risk_score')} ({ahp_result.get('risk_level')})\n"
                f"- MITRE ATT&CK: {graph_ctx['technique_id']} - {graph_ctx['technique_name']}\n"
                f"- Target Criticality: {graph_ctx['target_criticality']}\n"
                f"Provide a concise 2-sentence summary hypothesis and prioritized containment recommendations."
            )

            try:
                # 1. External Ollama format
                if self.provider == "ollama":
                    url = f"{self.api_base.rstrip('/')}/api/generate"
                    res = requests.post(
                        url,
                        json={
                            "model": self.model_name,
                            "prompt": prompt,
                            "stream": False,
                        },
                        timeout=self.timeout,
                    )
                    if res.status_code == 200:
                        explanation_text = res.json().get("response")

                # 2. OpenAI-compatible format (OpenAI, Groq, Together, vLLM, OpenRouter, Azure)
                else:
                    url = f"{self.api_base.rstrip('/')}/chat/completions"
                    headers = {"Content-Type": "application/json"}
                    if self.api_key:
                        headers["Authorization"] = f"Bearer {self.api_key}"

                    payload = {
                        "model": self.model_name,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a senior cybersecurity incident responder assisting in real-time SOC alert triage."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 300,
                        "temperature": 0.2,
                    }
                    res = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
                    if res.status_code == 200:
                        data = res.json()
                        explanation_text = data["choices"][0]["message"]["content"]
            except Exception:
                # If external LLM times out or is unreachable, continue cleanly with fallback
                pass

        if not explanation_text:
            score = ahp_result.get("final_risk_score", 0.0)
            level = ahp_result.get("risk_level", "low").upper()
            explanation_text = (
                f"Analyst Hypothesis: Observed {alert_dict.get('alert_type')} activity originating from "
                f"{alert_dict.get('src_ip')} targeting internal asset {alert_dict.get('dst_ip')} with an "
                f"AHP dynamic score of {score:.1f} ({level} Priority). Contextual correlation indicates alignment "
                f"with MITRE ATT&CK {graph_ctx['technique_id']} ({graph_ctx['technique_name']}). Target asset "
                f"is designated as {graph_ctx['target_criticality'].upper()} business criticality."
            )

        return {
            "rag_explanation": explanation_text.strip(),
            "mitre_attack_id": graph_ctx["technique_id"],
            "mitre_attack_name": graph_ctx["technique_name"],
            "recommended_actions": graph_ctx["mitigations"],
        }
