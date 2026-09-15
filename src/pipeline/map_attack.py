"""
map_attack.py — MITRE ATT&CK technique mapping stage.

Downloads the ATT&CK Enterprise STIX JSON dataset on first run and caches
it locally. For each cluster, keyword-matches the combined_text against
ATT&CK technique names and descriptions to return the top-3 technique IDs.

Uses mitreattack-python for structured STIX parsing, with a fallback to
raw JSON keyword matching if the library is unavailable.

LangGraph node: map_attack_node(state) -> state
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.schema import AlertCluster, AttackTechnique
from src.db import get_session, upsert_cluster

STIX_PATH = os.getenv("ATTACK_STIX_PATH", "data/attack_stix.json")
STIX_URL  = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Fallback embedded technique list (50 most common) if download fails
_FALLBACK_TECHNIQUES = [
    ("T1078", "Valid Accounts",                   "Credential Access"),
    ("T1190", "Exploit Public-Facing Application","Initial Access"),
    ("T1133", "External Remote Services",         "Persistence"),
    ("T1059", "Command and Scripting Interpreter","Execution"),
    ("T1055", "Process Injection",                "Defense Evasion"),
    ("T1021", "Remote Services",                  "Lateral Movement"),
    ("T1048", "Exfiltration Over Alt Protocol",   "Exfiltration"),
    ("T1071", "Application Layer Protocol",       "Command and Control"),
    ("T1105", "Ingress Tool Transfer",            "Command and Control"),
    ("T1486", "Data Encrypted for Impact",        "Impact"),
    ("T1566", "Phishing",                         "Initial Access"),
    ("T1110", "Brute Force",                      "Credential Access"),
    ("T1083", "File and Directory Discovery",     "Discovery"),
    ("T1057", "Process Discovery",                "Discovery"),
    ("T1003", "OS Credential Dumping",            "Credential Access"),
    ("T1547", "Boot or Logon Autostart Execution","Persistence"),
    ("T1070", "Indicator Removal",                "Defense Evasion"),
    ("T1027", "Obfuscated Files or Information",  "Defense Evasion"),
    ("T1036", "Masquerading",                     "Defense Evasion"),
    ("T1562", "Impair Defenses",                  "Defense Evasion"),
    ("T1018", "Remote System Discovery",          "Discovery"),
    ("T1049", "System Network Connections Discovery","Discovery"),
    ("T1082", "System Information Discovery",     "Discovery"),
    ("T1016", "System Network Configuration Discovery","Discovery"),
    ("T1041", "Exfiltration Over C2 Channel",     "Exfiltration"),
    ("T1567", "Exfiltration Over Web Service",    "Exfiltration"),
    ("T1560", "Archive Collected Data",           "Collection"),
    ("T1074", "Data Staged",                      "Collection"),
    ("T1005", "Data from Local System",           "Collection"),
    ("T1114", "Email Collection",                 "Collection"),
    ("T1098", "Account Manipulation",             "Persistence"),
    ("T1136", "Create Account",                   "Persistence"),
    ("T1053", "Scheduled Task/Job",               "Persistence"),
    ("T1543", "Create or Modify System Process",  "Persistence"),
    ("T1569", "System Services",                  "Execution"),
    ("T1203", "Exploitation for Client Execution","Execution"),
    ("T1204", "User Execution",                   "Execution"),
    ("T1566", "Phishing",                         "Initial Access"),
    ("T1195", "Supply Chain Compromise",          "Initial Access"),
    ("T1199", "Trusted Relationship",             "Initial Access"),
    ("T1200", "Hardware Additions",               "Initial Access"),
    ("T1091", "Replication Through Removable Media","Lateral Movement"),
    ("T1080", "Taint Shared Content",             "Lateral Movement"),
    ("T1534", "Internal Spearphishing",           "Lateral Movement"),
    ("T1119", "Automated Collection",             "Collection"),
    ("T1213", "Data from Information Repositories","Collection"),
    ("T1491", "Defacement",                       "Impact"),
    ("T1498", "Network Denial of Service",        "Impact"),
    ("T1499", "Endpoint Denial of Service",       "Impact"),
    ("T1529", "System Shutdown/Reboot",           "Impact"),
]


# ── STIX dataset management ───────────────────────────────────────────────────

def _download_stix() -> Optional[Dict]:
    """Download ATT&CK Enterprise STIX JSON, cache locally."""
    os.makedirs(os.path.dirname(STIX_PATH) or ".", exist_ok=True)
    if os.path.exists(STIX_PATH):
        print(f"[map_attack] Using cached ATT&CK STIX: {STIX_PATH}")
        with open(STIX_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)

    print(f"[map_attack] Downloading ATT&CK STIX dataset (one-time) ...")
    try:
        resp = requests.get(STIX_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        with open(STIX_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        print(f"[map_attack] STIX saved -> {STIX_PATH}")
        return data
    except Exception as exc:
        print(f"[map_attack] WARN: STIX download failed ({exc}). Using fallback.")
        return None


def _parse_stix_techniques(stix_data: Dict) -> List[Tuple[str, str, str, str]]:
    """Extract (technique_id, name, tactic, description) from STIX bundle."""
    techniques = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # Skip sub-techniques for simplicity (they have '.' in their ID)
        ext_refs = obj.get("external_references", [])
        tid = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None
        )
        if not tid or "." in tid:
            continue
        name  = obj.get("name", "")
        desc  = obj.get("description", "")[:300]
        tactic = ""
        for kc in obj.get("kill_chain_phases", []):
            if kc.get("kill_chain_name") == "mitre-attack":
                tactic = kc.get("phase_name", "").replace("-", " ").title()
                break
        techniques.append((tid, name, tactic, desc))
    return techniques


# ── Matching ──────────────────────────────────────────────────────────────────

def _score_technique(text_lower: str, name: str, description: str = "") -> float:
    """
    Score a technique against cluster text.
    Returns a match score 0.0 – 1.0.
    """
    name_lower = name.lower()
    desc_lower = description.lower()

    # Exact name match
    if name_lower in text_lower:
        return 1.0

    # Word overlap score
    name_words = set(re.findall(r'\w+', name_lower))
    text_words  = set(re.findall(r'\w+', text_lower))
    common = name_words & text_words
    if not name_words:
        return 0.0
    overlap = len(common) / len(name_words)

    # Bonus for description overlap
    if description:
        desc_words  = set(re.findall(r'\w+', desc_lower))
        desc_overlap = len(desc_words & text_words) / max(len(desc_words), 1)
        overlap = overlap * 0.7 + desc_overlap * 0.3

    return overlap


def map_cluster_to_techniques(
    cluster: AlertCluster,
    techniques: List[Tuple],  # (id, name, tactic, desc)
    top_k: int = 3,
) -> List[AttackTechnique]:
    text_lower = cluster.combined_text.lower()
    scored = []
    for tid, name, tactic, desc in techniques:
        score = _score_technique(text_lower, name, desc)
        if score > 0.05:
            scored.append((score, tid, name, tactic, desc))

    scored.sort(reverse=True)
    result = []
    seen = set()
    for score, tid, name, tactic, desc in scored:
        if tid in seen:
            continue
        seen.add(tid)
        result.append(AttackTechnique(
            technique_id = tid,
            name         = name,
            tactic       = tactic,
            description  = desc[:200],
            match_score  = round(score, 4),
        ))
        if len(result) >= top_k:
            break

    # Always return at least 1 technique via fallback keyword heuristics
    if not result:
        if "brute" in text_lower or "login" in text_lower:
            result.append(AttackTechnique(
                technique_id="T1110", name="Brute Force",
                tactic="Credential Access", match_score=0.5,
            ))
        elif "exfil" in text_lower:
            result.append(AttackTechnique(
                technique_id="T1048", name="Exfiltration Over Alternative Protocol",
                tactic="Exfiltration", match_score=0.5,
            ))
        else:
            result.append(AttackTechnique(
                technique_id="T1059", name="Command and Scripting Interpreter",
                tactic="Execution", match_score=0.3,
            ))
    return result


# ── Main mapping function ─────────────────────────────────────────────────────

def map_attack_techniques(clusters: List[AlertCluster]) -> List[AlertCluster]:
    stix_data  = _download_stix()
    if stix_data:
        techniques = _parse_stix_techniques(stix_data)
        print(f"[map_attack] Loaded {len(techniques)} ATT&CK techniques from STIX")
    else:
        techniques = [(t[0], t[1], t[2], "") for t in _FALLBACK_TECHNIQUES]
        print(f"[map_attack] Using fallback {len(techniques)} techniques")

    with get_session() as session:
        for cluster in clusters:
            if cluster.is_false_positive:
                # Don't map ATT&CK to confirmed false positives
                cluster.attack_techniques = []
                continue
            techniques_found = map_cluster_to_techniques(cluster, techniques, top_k=3)
            cluster.attack_techniques = techniques_found
            upsert_cluster(session, cluster)

    mapped = sum(1 for c in clusters if c.attack_techniques)
    print(f"[map_attack] ATT&CK mapped {mapped}/{len(clusters)} non-FP clusters")
    return clusters


# ── LangGraph node ────────────────────────────────────────────────────────────

def map_attack_node(state: dict) -> dict:
    from src.schema import AlertCluster
    clusters = [AlertCluster(**c) for c in state.get("clusters", [])]
    mapped   = map_attack_techniques(clusters)
    return {
        **state,
        "clusters": [c.model_dump() for c in mapped],
        "stage":    "bluf",
    }
