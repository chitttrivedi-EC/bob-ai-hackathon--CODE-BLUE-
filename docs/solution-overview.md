# Solution Overview — ThreatLens AI

## Executive Summary

ThreatLens AI is a five-stage AI pipeline that transforms raw, heterogeneous defense alerts into ranked, commander-ready BLUF intelligence briefs — automatically, in near-real-time.

The pipeline is built on production-grade, open-source components orchestrated by LangGraph, with IBM watsonx Granite-3 as the intelligence synthesis engine for final BLUF generation.

---

## How ThreatLens AI Addresses Each D2 Requirement

### 1. Multi-Source Ingestion & Normalization

| Source | Format | Parser |
|---|---|---|
| SIEM | JSON event logs | `SIEMParser` |
| Satellite Feed | JSON geo + signal metadata | `SatelliteParser` |
| Cyber Sensors | JSON/CEF IDS signatures | `CyberSensorParser` |
| Intel Reports | OSINT JSON bulletins | `IntelReportParser` |

All four parsers share a single registry pattern and output `NormalizedAlert` Pydantic objects to a common SQLite schema. Adding a fifth source type requires only one new parser class — no pipeline changes needed.

### 2. Cross-Source Semantic Correlation

ThreatLens uses **sentence-transformers** (`all-MiniLM-L6-v2`) to embed each alert's natural-language description into a 384-dimensional semantic vector. A FAISS `IndexFlatIP` index provides sub-millisecond approximate nearest-neighbour search across tens of thousands of alerts.

A **Union-Find algorithm** groups alerts whose cosine similarity exceeds a configurable threshold (default: 0.75). This means:

- A SIEM alert about "lateral movement from 185.220.101.42" and an OSINT bulletin about "APT28 using lateral movement via SMB" will be grouped into the same cluster — because their *meaning* is similar, not because they share keywords.
- Cross-source clusters (where multiple source types are represented) receive a confidence boost in the classifier stage.

### 3. Genuine Threat vs. False Positive Classification

A **scikit-learn RandomForestClassifier** is trained on 10 features extracted from each cluster:

- Maximum severity score (ordinal)
- Source type diversity (# of distinct sources)
- Alert count in cluster
- Average intra-cluster similarity
- Cross-source flag (strongest single predictor)
- Presence flags for each source type (SIEM, satellite, cyber_sensor, intel_report)
- CVE reference count in cluster text

The model is trained on the ground-truth labels embedded in the synthetic data (a proportion of alerts are explicitly labeled as false positives). The trained model is persisted with `joblib` for Streamlit hot-reloading.

**Result:** Clusters are assigned a `threat_score` (0–1). Clusters below 0.35 are flagged as false positives and excluded from BLUF generation. This directly reduces analyst workload on noise.

### 4. MITRE ATT&CK Technique Mapping

The ATT&CK Enterprise STIX JSON dataset is downloaded once from the public MITRE GitHub repository and cached locally. For each genuine-threat cluster:

1. The combined alert text is matched against ATT&CK technique names and descriptions via weighted keyword overlap scoring.
2. The top-3 technique IDs (e.g., T1078 Valid Accounts, T1048 Exfiltration Over Alternative Protocol) are attached to the cluster.
3. These techniques are surfaced in the BLUF prompt and rendered as chips in the Streamlit dashboard.

This gives commanders and analysts immediate ATT&CK context without requiring manual TTP mapping.

### 5. BLUF Generation via IBM watsonx Granite-3

**This is the IBM Bob integration point.**

For each prioritised cluster, the pipeline constructs a structured prompt containing:
- Alert source types and count
- Maximum severity level
- Threat score (as a confidence percentage)
- Combined alert summary text (truncated to 800 characters for context window efficiency)
- ATT&CK techniques identified

The prompt is submitted to `ibm_watsonx_ai.foundation_models.ModelInference` using the **`ibm/granite-3-8b-instruct`** model. The response is parsed into a structured `BLUFBrief` object with five mandatory sections:

```
BOTTOM_LINE:         One-sentence executive summary
CONFIDENCE:          HIGH / MEDIUM / LOW
SUPPORTING_DETAIL:   Evidence from correlated alerts
TECHNIQUES_SUMMARY:  ATT&CK technique interpretation
RECOMMENDED_ACTION:  Actionable step for commander
CLASSIFICATION:      Handling caveat
```

If watsonx credentials are not configured, the pipeline falls back to a rich, template-generated BLUF that is still well-formed and useful for UI demonstration — but clearly marked as a fallback.

### 6. Priority Ranking Dashboard

The Streamlit dashboard provides four views:

| Tab | Content |
|---|---|
| Raw Alerts | All ingested alerts with source-type badges, severity color-coding, and filter controls |
| Correlated Clusters | Cluster cards showing which alerts were linked, similarity scores, source diversity |
| Priority Queue | Ranked list by threat_score with visual score bars and FP badges |
| BLUF Briefs | Formatted intelligence cards with ATT&CK chip widgets, confidence indicators, and recommended actions |

---

## What Makes This Novel

1. **Semantic cross-source correlation** — not keyword matching. Two alerts in completely different formats about the same incident are linked by meaning, not by shared strings.
2. **End-to-end LangGraph orchestration** — the entire pipeline is a stateful graph, making each stage independently testable, replaceable, and extensible.
3. **IBM Granite-3 as BLUF author** — the LLM is not decorative; it synthesises structured intelligence output from multi-source evidence, mimicking how a senior analyst would write a commander brief.
4. **False-positive triage at cluster level** — by classifying groups of correlated alerts rather than individual alerts, the classifier has access to cross-source evidence that makes it significantly more accurate.
