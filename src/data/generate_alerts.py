"""
generate_alerts.py — Seeded synthetic alert generator for ThreatLens AI.

Produces realistic (but entirely fictional) defense alerts across 4 formats:
  1. SIEM alerts          (JSON)
  2. Satellite feed metadata (JSON)
  3. Cyber sensor logs    (JSON/CEF-style)
  4. Intel reports        (OSINT-style JSON)

The generator intentionally embeds:
  - Cross-source DUPLICATE clusters: the same underlying incident described
    independently by ≥2 source types (correlation engine must link these)
  - Seeded FALSE POSITIVES: plausible-looking alerts labeled is_false_positive=True
    (classifier must score these < 0.3)

Usage:
  python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json
  python src/data/generate_alerts.py --seed 42 --count 300 --output data/synthetic_alerts.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# ── Constants — realistic but fictional data ──────────────────────────────────

INTERNAL_IPS = [
    "10.0.1.{}", "10.0.2.{}", "192.168.10.{}", "192.168.20.{}"
]
EXTERNAL_IPS = [
    "185.220.101.{}", "194.165.16.{}", "91.108.4.{}", "45.83.64.{}", "5.39.{}.{}"
]
COUNTRIES    = ["RU", "CN", "IR", "KP", "Unknown"]
ACTORS       = [
    "APT28", "APT41", "Lazarus Group", "Charming Kitten",
    "Sandworm", "UNC2452", "FIN7", "Unknown"
]
CVES = [
    "CVE-2024-21762", "CVE-2023-44487", "CVE-2024-3400",
    "CVE-2024-1709",  "CVE-2023-23397", "CVE-2022-30190"
]
TECHNIQUES = [
    ("T1078", "Valid Accounts"),
    ("T1190", "Exploit Public-Facing Application"),
    ("T1133", "External Remote Services"),
    ("T1059", "Command and Scripting Interpreter"),
    ("T1055", "Process Injection"),
    ("T1021", "Remote Services"),
    ("T1048", "Exfiltration Over Alternative Protocol"),
    ("T1071", "Application Layer Protocol"),
    ("T1105", "Ingress Tool Transfer"),
    ("T1486", "Data Encrypted for Impact"),
]
SAT_IDS     = ["USA-327", "KH-11-12", "AEHF-7", "WGS-11+", "Milstar-6"]
SAT_ANOMALIES = [
    "unexpected attitude change",
    "signal jamming detected",
    "frequency deviation",
    "unauthorized uplink attempt",
    "orbit insertion anomaly",
]
IDS_SIGS    = [
    "ET TROJAN Cobalt Strike Beacon",
    "ET SCAN Rapid SSH Scanning",
    "ET DROP Known Bad CVE-2024-21762 Exploit Attempt",
    "ET POLICY SMB Administrator Login",
    "ET INFO DNS Query for Dynamic DNS Domain",
    "INDICATOR-SCAN SSH brute force login attempt",
    "MALWARE-CNC Known RAT Beacon",
]
FALSE_POSITIVE_EVENTS = [
    "scheduled vulnerability scan",
    "authorized pen-test traffic",
    "firewall rule test",
    "routine patch deployment",
    "backup job high-bandwidth transfer",
    "compliance scan from approved vendor",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def rng_ip(rng: random.Random, internal: bool = False) -> str:
    template = rng.choice(INTERNAL_IPS if internal else EXTERNAL_IPS)
    parts = template.count("{}")
    return template.format(*[rng.randint(1, 254) for _ in range(parts)])


def rng_ts(rng: random.Random, base: datetime, jitter_minutes: int = 30) -> str:
    delta = timedelta(minutes=rng.randint(-jitter_minutes, jitter_minutes))
    return (base + delta).isoformat() + "Z"


def rng_severity(rng: random.Random, weights=None) -> str:
    levels   = ["critical", "high", "medium", "low", "info"]
    weights  = weights or [0.10, 0.25, 0.35, 0.20, 0.10]
    return rng.choices(levels, weights=weights)[0]


# ── Source-specific generators ────────────────────────────────────────────────

def make_siem_alert(
    rng: random.Random, base_ts: datetime,
    is_fp: bool = False, incident_seed: Optional[Dict] = None
) -> Dict[str, Any]:
    src_ip  = incident_seed.get("src_ip",  rng_ip(rng)) if incident_seed else rng_ip(rng)
    dst_ip  = incident_seed.get("dst_ip",  rng_ip(rng, True)) if incident_seed else rng_ip(rng, True)
    actor   = incident_seed.get("actor",   rng.choice(ACTORS)) if incident_seed else rng.choice(ACTORS)
    cve     = incident_seed.get("cve",     rng.choice(CVES)) if incident_seed else rng.choice(CVES)

    if is_fp:
        event_type = rng.choice(FALSE_POSITIVE_EVENTS)
        severity   = rng.choice(["low", "info", "medium"])
        description = (
            f"SIEM flagged {event_type} from {src_ip} to {dst_ip}. "
            f"Traffic pattern matched alert rule but source is whitelisted."
        )
    else:
        event_type = rng.choice([
            "brute_force_login", "lateral_movement", "data_exfiltration",
            "c2_beacon", "privilege_escalation", "persistence_mechanism"
        ])
        severity = rng_severity(rng, [0.15, 0.30, 0.30, 0.15, 0.10])
        description = (
            f"SIEM detected {event_type.replace('_',' ')} from external host {src_ip} "
            f"targeting internal asset {dst_ip}. Exploit attempt using {cve} observed. "
            f"Attributed to threat actor cluster {actor}."
        )

    return {
        "source_type":        "siem",
        "alert_id":           str(uuid.uuid4()),
        "timestamp":          rng_ts(rng, base_ts),
        "severity":           severity,
        "event_type":         event_type,
        "source_ip":          src_ip,
        "destination_ip":     dst_ip,
        "description":        description,
        "rule_name":          f"RULE-{rng.randint(1000, 9999)}",
        "hostname":           f"WIN-{rng.randint(100,999)}.corp.mil",
        "cve_ids":            [cve] if not is_fp else [],
        "actor":              actor if not is_fp else "N/A",
        "is_false_positive":  is_fp,
    }


def make_satellite_alert(
    rng: random.Random, base_ts: datetime,
    is_fp: bool = False, incident_seed: Optional[Dict] = None
) -> Dict[str, Any]:
    sat_id   = incident_seed.get("sat_id", rng.choice(SAT_IDS)) if incident_seed else rng.choice(SAT_IDS)
    anomaly  = incident_seed.get("anomaly", rng.choice(SAT_ANOMALIES)) if incident_seed else rng.choice(SAT_ANOMALIES)
    lat      = round(rng.uniform(-90, 90), 4)
    lon      = round(rng.uniform(-180, 180), 4)

    if is_fp:
        anomaly  = "scheduled station-keeping maneuver"
        severity = "info"
        description = (
            f"Satellite {sat_id} executed planned station-keeping burn at "
            f"({lat}, {lon}). Nominal operation — flagged by automated threshold."
        )
    else:
        severity = rng_severity(rng, [0.10, 0.30, 0.35, 0.20, 0.05])
        description = (
            f"Satellite {sat_id} reporting {anomaly} at position ({lat}, {lon}). "
            f"Signal-to-noise ratio degraded by {rng.randint(15,45)}%. "
            f"Possible electronic warfare / jamming activity in region."
        )

    return {
        "source_type":       "satellite",
        "feed_id":           str(uuid.uuid4()),
        "timestamp":         rng_ts(rng, base_ts),
        "severity":          severity,
        "satellite_id":      sat_id,
        "latitude":          lat,
        "longitude":         lon,
        "anomaly_type":      anomaly,
        "description":       description,
        "snr_degradation_pct": rng.randint(0, 60) if not is_fp else 0,
        "is_false_positive": is_fp,
    }


def make_cyber_sensor_alert(
    rng: random.Random, base_ts: datetime,
    is_fp: bool = False, incident_seed: Optional[Dict] = None
) -> Dict[str, Any]:
    src_ip   = incident_seed.get("src_ip", rng_ip(rng)) if incident_seed else rng_ip(rng)
    dst_ip   = incident_seed.get("dst_ip", rng_ip(rng, True)) if incident_seed else rng_ip(rng, True)
    sig_name = rng.choice(IDS_SIGS)

    if is_fp:
        sig_name  = "ET SCAN Nessus Vulnerability Scanner"
        severity  = "low"
        description = (
            f"IDS signature {sig_name} triggered from {src_ip} to {dst_ip}. "
            f"Source confirmed as authorized Nessus scanner — false positive."
        )
    else:
        severity = rng_severity(rng, [0.12, 0.28, 0.32, 0.18, 0.10])
        proto    = rng.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS"])
        bytes_tx = rng.randint(512, 10_000_000)
        description = (
            f"Cyber sensor {sig_name} triggered. {proto} traffic from {src_ip} "
            f"to {dst_ip}, {bytes_tx:,} bytes. "
            f"Signature confidence: {rng.randint(70,99)}%. "
            f"Pattern consistent with C2 beaconing or lateral movement."
        )

    return {
        "source_type":       "cyber_sensor",
        "sensor_id":         f"SENSOR-{rng.randint(1,20):02d}",
        "log_id":            str(uuid.uuid4()),
        "timestamp":         rng_ts(rng, base_ts),
        "severity":          severity,
        "signature_id":      f"SID-{rng.randint(100000,999999)}",
        "signature_name":    sig_name,
        "protocol":          rng.choice(["TCP", "UDP", "ICMP"]),
        "source_ip":         src_ip,
        "dest_ip":           dst_ip,
        "bytes_transferred": rng.randint(512, 10_000_000),
        "description":       description,
        "is_false_positive": is_fp,
    }


def make_intel_report(
    rng: random.Random, base_ts: datetime,
    is_fp: bool = False, incident_seed: Optional[Dict] = None
) -> Dict[str, Any]:
    actor    = incident_seed.get("actor", rng.choice(ACTORS)) if incident_seed else rng.choice(ACTORS)
    ttps     = [t[0] for t in rng.choices(TECHNIQUES, k=rng.randint(2, 4))]
    cve      = incident_seed.get("cve", rng.choice(CVES)) if incident_seed else rng.choice(CVES)
    country  = rng.choice(COUNTRIES)

    if is_fp:
        description = (
            f"Open-source report from social media mentions actor {actor}. "
            f"Low confidence — no technical indicators corroborated. "
            f"Likely disinformation or misattribution. Recommend monitoring only."
        )
        severity = "low"
        confidence = round(rng.uniform(0.1, 0.35), 2)
    else:
        description = (
            f"OSINT intelligence bulletin: Threat actor {actor} (origin: {country}) "
            f"has been observed leveraging {cve} in targeted operations against "
            f"defense and aerospace entities. TTPs observed: {', '.join(ttps)}. "
            f"Campaign appears ongoing with high operational tempo."
        )
        severity   = rng_severity(rng, [0.20, 0.35, 0.30, 0.10, 0.05])
        confidence = round(rng.uniform(0.55, 0.95), 2)

    return {
        "source_type":       "intel_report",
        "report_id":         f"INTEL-{rng.randint(1000,9999)}",
        "timestamp":         rng_ts(rng, base_ts),
        "severity":          severity,
        "threat_actor":      actor,
        "country_of_origin": country,
        "ttps":              ttps,
        "cve_ids":           [cve] if not is_fp else [],
        "description":       description,
        "confidence":        confidence,
        "source_name":       rng.choice([
            "MISP feed", "AlienVault OTX", "Recorded Future",
            "Mandiant Intel", "CrowdStrike Adversary Intel"
        ]),
        "is_false_positive": is_fp,
    }


# ── Incident cluster factory — generates correlated cross-source groups ───────

def make_incident_cluster(rng: random.Random, base_ts: datetime) -> List[Dict]:
    """
    Creates 2–4 alerts from DIFFERENT sources that describe the same incident.
    Used to prove the correlation engine works.
    """
    src_ip  = rng_ip(rng)
    dst_ip  = rng_ip(rng, True)
    actor   = rng.choice(ACTORS)
    cve     = rng.choice(CVES)
    sat_id  = rng.choice(SAT_IDS)
    anomaly = rng.choice(SAT_ANOMALIES)

    seed = dict(src_ip=src_ip, dst_ip=dst_ip, actor=actor, cve=cve,
                sat_id=sat_id, anomaly=anomaly)

    generators = [
        make_siem_alert,
        make_satellite_alert,
        make_cyber_sensor_alert,
        make_intel_report,
    ]
    # Pick 2–4 sources for this incident
    chosen = rng.sample(generators, k=rng.randint(2, 4))
    alerts = []
    for gen in chosen:
        alert = gen(rng, base_ts, is_fp=False, incident_seed=seed)
        alerts.append(alert)
    return alerts


# ── Main generator ────────────────────────────────────────────────────────────

def generate(seed: int, total: int = 200) -> List[Dict]:
    rng      = random.Random(seed)
    base_ts  = datetime(2024, 9, 1, 0, 0, 0)
    alerts   = []

    # 1. Generate N_CLUSTERS correlated incident groups (cross-source)
    N_CLUSTERS = max(5, total // 20)
    for _ in range(N_CLUSTERS):
        cluster_alerts = make_incident_cluster(rng, base_ts)
        alerts.extend(cluster_alerts)

    # 2. Fill remaining quota with independent alerts (mix of TP & FP)
    remaining = total - len(alerts)
    generators = [
        make_siem_alert,
        make_satellite_alert,
        make_cyber_sensor_alert,
        make_intel_report,
    ]
    fp_rate = 0.25   # 25% of independent alerts are false positives
    for i in range(remaining):
        gen    = generators[i % len(generators)]
        is_fp  = (rng.random() < fp_rate)
        offset = timedelta(hours=rng.randint(0, 72))
        alert  = gen(rng, base_ts + offset, is_fp=is_fp)
        alerts.append(alert)

    # Shuffle so clusters aren't contiguous in the file
    rng.shuffle(alerts)
    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic defense alerts for ThreatLens AI"
    )
    parser.add_argument("--seed",   type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--count",  type=int, default=200,
                        help="Total alert count (default: 200)")
    parser.add_argument("--output", type=str, default="data/synthetic_alerts.json",
                        help="Output file path")
    args = parser.parse_args()

    print(f"[generator] seed={args.seed}  count={args.count}  output={args.output}")
    alerts = generate(seed=args.seed, total=args.count)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2, default=str)

    true_positives  = sum(1 for a in alerts if not a.get("is_false_positive"))
    false_positives = sum(1 for a in alerts if a.get("is_false_positive"))
    src_counts = {}
    for a in alerts:
        src_counts[a["source_type"]] = src_counts.get(a["source_type"], 0) + 1

    print(f"[generator] Generated {len(alerts)} alerts:")
    print(f"            True positives : {true_positives}")
    print(f"            False positives: {false_positives}")
    print(f"            By source type : {src_counts}")
    print(f"[generator] Saved -> {args.output}")


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        getattr(sys.stdout, "reconfigure")(encoding="utf-8", errors="replace")
    main()
