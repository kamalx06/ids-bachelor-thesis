"""
MITRE ATT&CK mapping for detection reasons.

The mapping is embedded as a Python dict so there's no external config
file to load and no schema drift between deployments. Extend by adding
entries to REASON_TO_TECHNIQUE.

Used by:
  - ids/ai_analysis.py — attaches `mitre_techniques` to the analysis result
  - storage/persistence.py — persists them into packet_logs.mitre_json
  - /analytics/api/mitre-coverage — aggregated view for the analytics page
"""

from __future__ import annotations

from typing import Any


# Top-level tactics in ATT&CK Enterprise order. Used for grouping on the
# analytics page and to define the coverage matrix.
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


# reason token (exact or prefix) -> technique
REASON_TO_TECHNIQUE: dict[str, dict[str, str]] = {
    # Application-layer attacks detected by the payload analyzer
    "http_SQLi":              {"technique": "T1190",     "tactic": "Initial Access",        "name": "Exploit Public-Facing Application"},
    "payload_SQLi":           {"technique": "T1190",     "tactic": "Initial Access",        "name": "Exploit Public-Facing Application"},
    "http_XSS":               {"technique": "T1059.007", "tactic": "Execution",             "name": "JavaScript/JScript"},
    "payload_XSS":            {"technique": "T1059.007", "tactic": "Execution",             "name": "JavaScript/JScript"},
    "http_Command_Injection": {"technique": "T1059",     "tactic": "Execution",             "name": "Command and Scripting Interpreter"},
    "payload_Command_Injection": {"technique": "T1059",  "tactic": "Execution",             "name": "Command and Scripting Interpreter"},
    "http_Path_Traversal":    {"technique": "T1083",     "tactic": "Discovery",             "name": "File and Directory Discovery"},
    "http_File_Inclusion":    {"technique": "T1190",     "tactic": "Initial Access",        "name": "Exploit Public-Facing Application"},
    "http_SSRF":              {"technique": "T1190",     "tactic": "Initial Access",        "name": "Exploit Public-Facing Application"},
    "http_Credential_Leak":   {"technique": "T1552",     "tactic": "Credential Access",     "name": "Unsecured Credentials"},
    "http_Malware_Indicators":{"technique": "T1105",     "tactic": "Command and Control",   "name": "Ingress Tool Transfer"},
    "http_Binary_Exploit":    {"technique": "T1203",     "tactic": "Execution",             "name": "Exploitation for Client Execution"},

    # Behavioral detectors
    "port_scan":              {"technique": "T1046",     "tactic": "Discovery",             "name": "Network Service Discovery"},
    "flood":                  {"technique": "T1498",     "tactic": "Impact",                "name": "Network Denial of Service"},

    # DNS heuristics
    "dns_tunnel_suspected":   {"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},
    "dns_high_entropy_qname": {"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},
    "dns_long_qname":         {"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},
    "dns_many_unique_queries":{"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},
    "dns_subdomain_churn":    {"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},
    "dns_txt_burst":          {"technique": "T1071.004", "tactic": "Command and Control",   "name": "DNS"},

    # Reputation signals
    "reputation_ip_malicious":   {"technique": "T1071",  "tactic": "Command and Control",   "name": "Application Layer Protocol"},
    "reputation_ip_suspicious":  {"technique": "T1071",  "tactic": "Command and Control",   "name": "Application Layer Protocol"},
    "reputation_url_malicious":  {"technique": "T1071",  "tactic": "Command and Control",   "name": "Application Layer Protocol"},
    "reputation_url_suspicious": {"technique": "T1071",  "tactic": "Command and Control",   "name": "Application Layer Protocol"},

    # Zeek-derived signals
    "zeek_port_scan":         {"technique": "T1046",     "tactic": "Discovery",             "name": "Network Service Discovery"},
    "zeek_syn_scan_pattern":  {"technique": "T1046",     "tactic": "Discovery",             "name": "Network Service Discovery"},
    "zeek_flag_dangerous":    {"technique": "T1046",     "tactic": "Discovery",             "name": "Network Service Discovery"},
    "zeek_flag_suspicious":   {"technique": "T1046",     "tactic": "Discovery",             "name": "Network Service Discovery"},

    # SSL-decrypted traffic path has no ML; still worth mapping
    "ml_skipped_no_features": None,  # explicitly unmapped
}


# Rank for de-duplication when multiple reasons map to the same technique.
# Higher wins. Also controls which entries survive the top-N cap.
_TACTIC_RANK = {t: i for i, t in enumerate(TACTICS)}


def classify(reasons: list[Any]) -> list[dict[str, str]]:
    """
    Map a list of reason tokens to ATT&CK techniques.

    Returns a list of dicts with keys: technique, tactic, name.
    Deduplicated by technique ID, ordered by tactic position and then
    technique ID, capped at 12 entries to keep packet_logs.mitre_json small.
    """
    if not reasons:
        return []

    found: dict[str, dict[str, str]] = {}

    for r in reasons:
        if not isinstance(r, str):
            continue
        entry = REASON_TO_TECHNIQUE.get(r)
        if entry is None and r.startswith("http_"):
            entry = REASON_TO_TECHNIQUE.get(r.lower())
        if entry is None and r.startswith("payload_"):
            entry = REASON_TO_TECHNIQUE.get(r.replace("payload_", "http_", 1))
        if not entry:
            continue
        tech = entry["technique"]
        if tech not in found:
            found[tech] = dict(entry)

    out = sorted(
        found.values(),
        key=lambda e: (_TACTIC_RANK.get(e["tactic"], 999), e["technique"]),
    )
    return out[:12]


def coverage() -> list[dict[str, str]]:
    """The full mapping as a flat list — used by the analytics coverage view."""
    seen = {}
    for entry in REASON_TO_TECHNIQUE.values():
        if not entry:
            continue
        if entry["technique"] not in seen:
            seen[entry["technique"]] = dict(entry)
    return sorted(
        seen.values(),
        key=lambda e: (_TACTIC_RANK.get(e["tactic"], 999), e["technique"]),
    )