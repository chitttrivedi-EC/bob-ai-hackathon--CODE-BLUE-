"""
schema.py — Pydantic data models for ThreatLens AI pipeline.

All pipeline stages exchange these typed objects, ensuring consistency
from raw alert ingestion through BLUF generation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


# ── Enumerations ─────────────────────────────────────────────────────────────

class SourceType(str, Enum):
    SIEM            = "siem"
    SATELLITE       = "satellite"
    CYBER_SENSOR    = "cyber_sensor"
    INTEL_REPORT    = "intel_report"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Raw (pre-normalisation) envelope ─────────────────────────────────────────

class RawAlert(BaseModel):
    """Source-agnostic envelope received from an ingestion channel."""
    source_type:  SourceType
    raw_payload:  Dict[str, Any]   # original JSON/CSV row as-parsed
    received_at:  datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingestion_id: str      = Field(default_factory=lambda: str(uuid.uuid4()))


# ── Normalised internal alert ─────────────────────────────────────────────────

class NormalizedAlert(BaseModel):
    """Unified schema for all alert types after source-specific parsing."""
    id:           str          = Field(default_factory=lambda: str(uuid.uuid4()))
    source_type:  SourceType
    severity:     SeverityLevel
    timestamp:    datetime

    # Human-readable summary used for embedding & BLUF
    raw_text:     str

    # Structured fields extracted by parsers
    source_ip:    Optional[str]   = None
    dest_ip:      Optional[str]   = None
    event_type:   Optional[str]   = None
    actor:        Optional[str]   = None
    location:     Optional[str]   = None
    cve_ids:      List[str]       = Field(default_factory=list)
    confidence:   float           = 1.0   # parser confidence 0–1

    # Ground-truth label (for synthetic data evaluation only)
    is_false_positive: Optional[bool] = None

    # Set by pipeline stages
    cluster_id:        Optional[str]  = None
    threat_score:      Optional[float] = None
    attack_techniques: List[str]      = Field(default_factory=list)

    # Stored embedding (list of floats; not persisted to DB — computed on-the-fly)
    embedding: Optional[List[float]] = Field(default=None, exclude=True)


# ── Cluster ───────────────────────────────────────────────────────────────────

class AlertCluster(BaseModel):
    """Group of correlated NormalizedAlerts describing the same incident."""
    cluster_id:       str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_ids:        List[str]
    source_types:     List[SourceType]
    max_severity:     SeverityLevel
    avg_similarity:   float              = 0.0
    combined_text:    str               = ""
    alert_count:      int               = 0

    # Set by classify stage
    threat_score:      Optional[float]  = None
    is_false_positive: Optional[bool]  = None

    # Set by map_attack stage
    attack_techniques: List[AttackTechnique] = Field(default_factory=list)

    # Set by bluf stage
    bluf: Optional[BLUFBrief] = None


# ── MITRE ATT&CK technique reference ─────────────────────────────────────────

class AttackTechnique(BaseModel):
    technique_id:   str    # e.g. "T1078"
    name:           str    # e.g. "Valid Accounts"
    tactic:         str    # e.g. "Initial Access"
    description:    str    = ""
    match_score:    float  = 0.0


# ── BLUF Brief ────────────────────────────────────────────────────────────────

class BLUFBrief(BaseModel):
    """
    Bottom Line Up Front brief — structured output of IBM watsonx Granite-3.

    Fields follow the standard military BLUF format adapted for cyber/defense:
      1. Bottom line (what happened, one sentence)
      2. Confidence level
      3. Supporting detail
      4. ATT&CK techniques
      5. Recommended action
      6. Classification/handling caveat
    """
    cluster_id:          str
    bottom_line:         str    # One-sentence executive summary
    confidence:          str    # HIGH / MEDIUM / LOW
    supporting_detail:   str    # 2–3 sentences of evidence
    techniques_summary:  str    # Prose description of ATT&CK techniques used
    recommended_action:  str    # Actionable next step for commander
    classification:      str    = "UNCLASSIFIED // FOR OFFICIAL USE ONLY"
    generated_by:        str    = "IBM watsonx Granite-3"
    generated_at:        datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_fallback:         bool   = False   # True if LLM call was unavailable


# ── Pipeline state (LangGraph) ───────────────────────────────────────────────

class PipelineState(BaseModel):
    """Shared state object passed between all LangGraph pipeline nodes."""
    input_file:      str                  = ""
    raw_alerts:      List[RawAlert]       = Field(default_factory=list)
    alerts:          List[NormalizedAlert] = Field(default_factory=list)
    clusters:        List[AlertCluster]   = Field(default_factory=list)
    briefs:          List[BLUFBrief]      = Field(default_factory=list)
    errors:          List[str]            = Field(default_factory=list)
    stage:           str                  = "init"


# ── Resolve forward references ────────────────────────────────────────────────
AlertCluster.model_rebuild()
