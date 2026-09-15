"""
ingest.py — Multi-source alert ingestion and normalisation stage.

Parser registry pattern: one parser class per SourceType.
All parsers output NormalizedAlert objects which are written to SQLite.

LangGraph node: ingest_node(state) -> state
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

# Allow running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.schema import (
    NormalizedAlert, SourceType, SeverityLevel
)
from src.db import get_session, upsert_alert


# ── Severity mapping ──────────────────────────────────────────────────────────

_SEV_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high":     SeverityLevel.HIGH,
    "medium":   SeverityLevel.MEDIUM,
    "low":      SeverityLevel.LOW,
    "info":     SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
}

def _parse_severity(raw: str) -> SeverityLevel:
    return _SEV_MAP.get(raw.lower(), SeverityLevel.MEDIUM)


def _parse_ts(raw: Any) -> datetime:
    """Parse ISO-8601 timestamp strings from synthetic data."""
    if isinstance(raw, datetime):
        return raw
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


# ── Parser base ───────────────────────────────────────────────────────────────

class BaseParser:
    source_type: SourceType

    def parse(self, payload: Dict[str, Any]) -> NormalizedAlert:
        raise NotImplementedError


# ── SIEM Parser ───────────────────────────────────────────────────────────────

class SIEMParser(BaseParser):
    source_type = SourceType.SIEM

    def parse(self, payload: Dict[str, Any]) -> NormalizedAlert:
        p = payload
        return NormalizedAlert(
            source_type  = SourceType.SIEM,
            severity     = _parse_severity(p.get("severity", "medium")),
            timestamp    = _parse_ts(p.get("timestamp", datetime.now(timezone.utc).isoformat())),
            raw_text     = p.get("description", ""),
            source_ip    = p.get("source_ip"),
            dest_ip      = p.get("destination_ip"),
            event_type   = p.get("event_type"),
            actor        = p.get("actor"),
            cve_ids      = p.get("cve_ids", []),
            confidence   = 0.95,
            is_false_positive = p.get("is_false_positive", False),
        )


# ── Satellite Parser ──────────────────────────────────────────────────────────

class SatelliteParser(BaseParser):
    source_type = SourceType.SATELLITE

    def parse(self, payload: Dict[str, Any]) -> NormalizedAlert:
        p = payload
        lat = p.get("latitude", 0)
        lon = p.get("longitude", 0)
        return NormalizedAlert(
            source_type = SourceType.SATELLITE,
            severity    = _parse_severity(p.get("severity", "medium")),
            timestamp   = _parse_ts(p.get("timestamp", datetime.now(timezone.utc).isoformat())),
            raw_text    = p.get("description", ""),
            event_type  = p.get("anomaly_type"),
            location    = f"{lat},{lon}",
            confidence  = 0.80,
            is_false_positive = p.get("is_false_positive", False),
        )


# ── Cyber Sensor Parser ───────────────────────────────────────────────────────

class CyberSensorParser(BaseParser):
    source_type = SourceType.CYBER_SENSOR

    def parse(self, payload: Dict[str, Any]) -> NormalizedAlert:
        p = payload
        return NormalizedAlert(
            source_type = SourceType.CYBER_SENSOR,
            severity    = _parse_severity(p.get("severity", "medium")),
            timestamp   = _parse_ts(p.get("timestamp", datetime.now(timezone.utc).isoformat())),
            raw_text    = p.get("description", ""),
            source_ip   = p.get("source_ip"),
            dest_ip     = p.get("dest_ip"),
            event_type  = p.get("signature_name"),
            confidence  = 0.90,
            is_false_positive = p.get("is_false_positive", False),
        )


# ── Intel Report Parser ───────────────────────────────────────────────────────

class IntelReportParser(BaseParser):
    source_type = SourceType.INTEL_REPORT

    def parse(self, payload: Dict[str, Any]) -> NormalizedAlert:
        p = payload
        return NormalizedAlert(
            source_type = SourceType.INTEL_REPORT,
            severity    = _parse_severity(p.get("severity", "medium")),
            timestamp   = _parse_ts(p.get("timestamp", datetime.now(timezone.utc).isoformat())),
            raw_text    = p.get("description", ""),
            actor       = p.get("threat_actor"),
            cve_ids     = p.get("cve_ids", []),
            confidence  = float(p.get("confidence", 0.7)),
            is_false_positive = p.get("is_false_positive", False),
        )


# ── Parser registry ───────────────────────────────────────────────────────────

_PARSERS: Dict[str, BaseParser] = {
    "siem":          SIEMParser(),
    "satellite":     SatelliteParser(),
    "cyber_sensor":  CyberSensorParser(),
    "intel_report":  IntelReportParser(),
}


# ── Public ingestion function ─────────────────────────────────────────────────

def ingest_alerts(input_file: str) -> List[NormalizedAlert]:
    """
    Load raw alert JSON, parse each with its source-specific parser,
    write to SQLite, and return the list of NormalizedAlert objects.
    """
    print(f"[ingest] Loading alerts from {input_file}")
    with open(input_file, "r", encoding="utf-8") as fh:
        raw_list: List[Dict] = json.load(fh)

    alerts: List[NormalizedAlert] = []
    errors: List[str] = []

    for raw in raw_list:
        src = raw.get("source_type", "").lower()
        parser = _PARSERS.get(src)
        if parser is None:
            errors.append(f"Unknown source_type '{src}' — skipped")
            continue
        try:
            alert = parser.parse(raw)
            alerts.append(alert)
        except Exception as exc:
            errors.append(f"Parse error for {src}: {exc}")

    # Persist to DB
    with get_session() as session:
        for alert in alerts:
            upsert_alert(session, alert)

    src_counts = {}
    for a in alerts:
        src_counts[a.source_type.value] = src_counts.get(a.source_type.value, 0) + 1

    print(f"[ingest] Parsed {len(alerts)} alerts | errors={len(errors)}")
    print(f"[ingest] Source breakdown: {src_counts}")
    if errors:
        for e in errors[:5]:
            print(f"[ingest]   WARN: {e}")
    return alerts


# ── LangGraph node ────────────────────────────────────────────────────────────

def ingest_node(state: dict) -> dict:
    alerts = ingest_alerts(state["input_file"])
    return {**state, "alerts": [a.model_dump() for a in alerts], "stage": "correlate"}
