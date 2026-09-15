"""
bluf.py — BLUF summary generation stage via IBM watsonx Granite-3.

This is the load-bearing IBM Bob integration point.

For each prioritised (non-FP) cluster the stage:
  1. Constructs a structured prompt with cluster metadata, severity,
     source types, alert summaries, and ATT&CK techniques
  2. Calls ibm_watsonx_ai.foundation_models.ModelInference.generate()
     with ibm/granite-3-8b-instruct
  3. Parses the response into a BLUFBrief Pydantic model
  4. Falls back to a rich template-based brief if API is unavailable

The fallback path still produces well-formed, readable briefs so judges
can evaluate the complete UI even without watsonx credentials.

LangGraph node: bluf_node(state) -> state
"""
from __future__ import annotations

import os
import re
import sys
import time
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.schema import AlertCluster, BLUFBrief, SeverityLevel
from src.db import get_session, upsert_cluster, BriefRow

# ── IBM watsonx config ────────────────────────────────────────────────────────

WATSONX_API_KEY    = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL        = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
WATSONX_MODEL_ID   = os.getenv("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct")

# Only generate BLUFs for clusters with threat_score above this threshold
BLUF_SCORE_THRESHOLD = 0.0   # generate for all non-FP clusters in demo

# ── Prompt construction ───────────────────────────────────────────────────────

_SEVERITY_CONF = {
    SeverityLevel.CRITICAL: "HIGH",
    SeverityLevel.HIGH:     "HIGH",
    SeverityLevel.MEDIUM:   "MEDIUM",
    SeverityLevel.LOW:      "LOW",
    SeverityLevel.INFO:     "LOW",
}


def _build_prompt(cluster: AlertCluster) -> str:
    techniques_str = ", ".join(
        f"{t.technique_id} ({t.name})"
        for t in cluster.attack_techniques
    ) or "None identified"

    source_types_str = ", ".join(
        s.value.replace("_", " ").upper()
        for s in cluster.source_types
    )

    severity_str = cluster.max_severity.value.upper()
    score_pct    = int((cluster.threat_score or 0.5) * 100)
    conf_level   = _SEVERITY_CONF.get(cluster.max_severity, "MEDIUM")

    prompt = f"""You are a senior cyber-defense analyst producing a classified threat intelligence brief.
Your output must strictly follow the BLUF (Bottom Line Up Front) format.

INCIDENT DATA:
- Alert Sources: {source_types_str}
- Max Severity: {severity_str}
- Threat Score: {score_pct}% confidence
- Number of correlated alerts: {cluster.alert_count}
- MITRE ATT&CK Techniques: {techniques_str}
- Combined alert summary:
{cluster.combined_text[:800]}

Produce a BLUF brief with EXACTLY these sections, each on its own line:
BOTTOM_LINE: <One sentence — what is happening, who is targeting whom>
CONFIDENCE: {conf_level}
SUPPORTING_DETAIL: <2-3 sentences — key technical evidence, source correlation>
TECHNIQUES_SUMMARY: <1-2 sentences — what the ATT&CK techniques tell us about adversary intent>
RECOMMENDED_ACTION: <One actionable step for the commander, starting with an imperative verb>
CLASSIFICATION: UNCLASSIFIED // FOR OFFICIAL USE ONLY

Write in a direct, professional military intelligence style. No preamble.
"""
    return prompt.strip()


# ── watsonx call ──────────────────────────────────────────────────────────────

_RETRY_DELAYS = [2, 4]   # seconds between attempts (3 total attempts)


def _call_watsonx(prompt: str) -> Optional[str]:
    """
    Calls IBM watsonx.ai ModelInference.generate() with exponential-backoff
    retry (3 attempts, 2 s / 4 s delays) to handle transient 'API overloaded'
    errors. Returns generated text or None if unavailable.
    """
    if not WATSONX_API_KEY or not WATSONX_PROJECT_ID:
        return None

    try:
        from ibm_watsonx_ai import Credentials, APIClient
        from ibm_watsonx_ai.foundation_models import ModelInference
        from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams
    except ImportError:
        print("[bluf] WARN: ibm-watsonx-ai not installed. Using fallback.")
        return None

    credentials = Credentials(url=WATSONX_URL, api_key=WATSONX_API_KEY)
    client      = APIClient(credentials, project_id=WATSONX_PROJECT_ID)
    model       = ModelInference(model_id=WATSONX_MODEL_ID, api_client=client)

    params = {
        GenParams.MAX_NEW_TOKENS:  512,
        GenParams.TEMPERATURE:     0.3,
        GenParams.TOP_P:           0.9,
        GenParams.STOP_SEQUENCES:  ["---", "```"],
    }

    last_exc: Optional[Exception] = None
    for attempt, delay in enumerate([0] + _RETRY_DELAYS, start=1):
        if delay:
            print(f"[bluf] Retrying watsonx (attempt {attempt}/3) after {delay}s...")
            time.sleep(delay)
        try:
            response = model.generate(prompt=prompt, params=params)
            generated_text = (
                response.get("results", [{}])[0].get("generated_text", "")
                if isinstance(response, dict)
                else str(response)
            )
            return generated_text.strip()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            print(f"[bluf] WARN: watsonx attempt {attempt} failed: {exc}")

    print(f"[bluf] WARN: All watsonx attempts exhausted ({last_exc}). Using fallback.")
    return None


# ── Response parsing ──────────────────────────────────────────────────────────

def _parse_response(text: str, cluster: AlertCluster) -> dict:
    """Extract BLUF fields from LLM-generated text."""
    fields = {}
    patterns = {
        "bottom_line":        r"BOTTOM_LINE:\s*(.+)",
        "confidence":         r"CONFIDENCE:\s*(.+)",
        "supporting_detail":  r"SUPPORTING_DETAIL:\s*(.+)",
        "techniques_summary": r"TECHNIQUES_SUMMARY:\s*(.+)",
        "recommended_action": r"RECOMMENDED_ACTION:\s*(.+)",
        "classification":     r"CLASSIFICATION:\s*(.+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            fields[key] = m.group(1).strip().split("\n")[0].strip()

    # Ensure required fields have values
    fields.setdefault("bottom_line",
        f"Threat cluster detected across {len(cluster.source_types)} source(s) "
        f"with {cluster.max_severity.value.upper()} severity.")
    fields.setdefault("confidence",
        _SEVERITY_CONF.get(cluster.max_severity, "MEDIUM"))
    fields.setdefault("supporting_detail",
        f"{cluster.alert_count} correlated alerts from "
        f"{', '.join(s.value.replace('_',' ') for s in cluster.source_types)}.")
    fields.setdefault("techniques_summary",
        ", ".join(f"{t.technique_id} {t.name}" for t in cluster.attack_techniques)
        or "No ATT&CK techniques identified.")
    fields.setdefault("recommended_action",
        "Escalate to SOC Tier 2 for immediate investigation.")
    fields.setdefault("classification",
        "UNCLASSIFIED // FOR OFFICIAL USE ONLY")
    return fields


# ── Template fallback (no watsonx credentials) ───────────────────────────────

def _build_fallback_brief(cluster: AlertCluster) -> BLUFBrief:
    """
    Produce a structured template-based BLUF when watsonx is unavailable.
    Well-formed and readable; clearly marked as fallback.
    """
    source_names = [s.value.replace("_", " ").title() for s in cluster.source_types]
    technique_names = [f"{t.technique_id} ({t.name})" for t in cluster.attack_techniques]

    sev = cluster.max_severity.value.upper()
    score_pct = int((cluster.threat_score or 0.5) * 100)

    return BLUFBrief(
        cluster_id = cluster.cluster_id,
        bottom_line = (
            f"{sev}-severity threat cluster correlated across "
            f"{', '.join(source_names)}, threat score {score_pct}%."
        ),
        confidence = _SEVERITY_CONF.get(cluster.max_severity, "MEDIUM"),
        supporting_detail = (
            f"{cluster.alert_count} alert(s) from {len(cluster.source_types)} "
            f"independent source(s) were semantically correlated (avg similarity "
            f"{cluster.avg_similarity:.2f}). Cross-source confirmation strengthens "
            f"confidence that this is a genuine incident rather than a false positive."
        ),
        techniques_summary = (
            f"Adversary TTPs include: {', '.join(technique_names)}. "
            f"This pattern is consistent with targeted intrusion activity."
        ) if technique_names else "No ATT&CK techniques identified in cluster text.",
        recommended_action = (
            "Isolate affected hosts, capture network traffic for forensic analysis, "
            "and escalate to Incident Response team within 30 minutes."
        ),
        classification = "UNCLASSIFIED // FOR OFFICIAL USE ONLY",
        generated_by   = "Template fallback (watsonx credentials not configured)",
        is_fallback    = True,
    )


# ── Main BLUF generation function ────────────────────────────────────────────

def generate_bluf_briefs(clusters: List[AlertCluster]) -> List[BLUFBrief]:
    briefs: List[BLUFBrief] = []
    watsonx_available = bool(WATSONX_API_KEY and WATSONX_PROJECT_ID)

    print(
        f"[bluf] IBM watsonx {'ENABLED' if watsonx_available else 'DISABLED (fallback mode)'}"
    )
    print(f"[bluf] Generating BLUF for {len([c for c in clusters if not c.is_false_positive])} non-FP clusters")

    with get_session() as session:
        for cluster in clusters:
            if cluster.is_false_positive:
                continue   # skip false positives — no brief needed

            if watsonx_available:
                prompt   = _build_prompt(cluster)
                raw_text = _call_watsonx(prompt)

                if raw_text:
                    fields = _parse_response(raw_text, cluster)
                    brief  = BLUFBrief(
                        cluster_id         = cluster.cluster_id,
                        bottom_line        = fields["bottom_line"],
                        confidence         = fields["confidence"],
                        supporting_detail  = fields["supporting_detail"],
                        techniques_summary = fields["techniques_summary"],
                        recommended_action = fields["recommended_action"],
                        classification     = fields.get("classification",
                                             "UNCLASSIFIED // FOR OFFICIAL USE ONLY"),
                        generated_by       = f"IBM watsonx ({WATSONX_MODEL_ID})",
                        is_fallback        = False,
                    )
                else:
                    brief = _build_fallback_brief(cluster)
            else:
                brief = _build_fallback_brief(cluster)

            cluster.bluf = brief
            upsert_cluster(session, cluster)

            # Also write to briefs table
            brief_row = BriefRow(
                cluster_id         = brief.cluster_id,
                bottom_line        = brief.bottom_line,
                confidence         = brief.confidence,
                supporting_detail  = brief.supporting_detail,
                techniques_summary = brief.techniques_summary,
                recommended_action = brief.recommended_action,
                classification     = brief.classification,
                generated_by       = brief.generated_by,
                generated_at       = brief.generated_at,
                is_fallback        = brief.is_fallback,
            )
            session.merge(brief_row)
            briefs.append(brief)

    watsonx_count = sum(1 for b in briefs if not b.is_fallback)
    fallback_count = len(briefs) - watsonx_count
    print(f"[bluf] Generated {len(briefs)} BLUF briefs "
          f"(watsonx={watsonx_count}, fallback={fallback_count})")
    return briefs


# ── LangGraph node ────────────────────────────────────────────────────────────

def bluf_node(state: dict) -> dict:
    from src.schema import AlertCluster
    clusters = [AlertCluster(**c) for c in state.get("clusters", [])]
    briefs   = generate_bluf_briefs(clusters)
    return {
        **state,
        "clusters": [c.model_dump() for c in clusters],
        "briefs":   [b.model_dump(mode="json") for b in briefs],
        "stage":    "done",
    }
