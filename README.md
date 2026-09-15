# ThreatLens AI
### Bob AI Hackathon — Problem D2: Threat Intelligence Correlation & Alert Prioritisation Assistant
**Track:** Defense & Aerospace | **Priority:** Critical Now

---

## Overview

ThreatLens AI is a production-quality AI pipeline that transforms thousands of heterogeneous daily defense alerts into ranked, commander-ready BLUF (Bottom Line Up Front) intelligence briefs — in near-real-time.

Built for the Bob AI Hackathon, ThreatLens directly addresses the D2 problem: defense analysts are drowning in alerts from SIEM systems, satellite feeds, cyber sensors, and OSINT reports. No human team can read them all. Missing a genuine threat is catastrophic; chasing false positives wastes critical resources.

---

## Features

- **Multi-source ingestion** — 4 distinct source parsers (SIEM, Satellite, Cyber Sensor, Intel Report) → unified schema
- **Semantic correlation** — sentence-transformers + FAISS clusters alerts describing the same incident across sources
- **Threat classification** — scikit-learn RandomForest separates genuine threats from false positives
- **MITRE ATT&CK mapping** — automatic technique ID assignment from the public STIX dataset
- **BLUF generation** — IBM watsonx Granite-3 produces structured commander-ready intelligence briefs
- **LangGraph orchestration** — all 5 stages wired as a stateful pipeline graph
- **Streamlit dashboard** — 4-tab real-time UI with severity badges, cluster cards, priority queue, and BLUF cards

---

## Architecture

```
SIEM · Satellite · Cyber Sensor · Intel Report
        ↓
   [INGEST] → [CORRELATE] → [CLASSIFY] → [MAP ATT&CK] → [BLUF]
   Parsers    FAISS+           sklearn      STIX JSON    IBM watsonx
              sent-xfmr       RandomForest  local cache  Granite-3
        ↓
   SQLite → Streamlit Dashboard
```

See [docs/architecture.md](docs/architecture.md) for the full Mermaid diagram and component table.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/YOUR_USERNAME/threat-intelligence-d2.git
cd threat-intelligence-d2
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — add WATSONX_API_KEY + WATSONX_PROJECT_ID for live BLUF

# 3. Generate synthetic alert data
python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json

# 4. Run the pipeline
python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db

# 5. Launch dashboard
streamlit run src/app.py
# Open: http://localhost:8501
```

See [docs/setup-guide.md](docs/setup-guide.md) for the complete step-by-step guide, prerequisites, environment variable reference, and troubleshooting table.

---

## IBM Bob Integration

IBM watsonx Granite-3 (`ibm/granite-3-8b-instruct`) is **load-bearing** in the BLUF generation stage.

For each prioritised threat cluster the pipeline:
1. Constructs a structured prompt from cluster metadata, alert summaries, and ATT&CK techniques
2. Calls `ibm_watsonx_ai.foundation_models.ModelInference.generate()`
3. Parses the LLM response into a structured `BLUFBrief` Pydantic model

Without credentials the pipeline falls back to template-based briefs so the complete UI is always demonstrable.

**SDK:** `ibm-watsonx-ai>=1.1.0`
**Model:** `ibm/granite-3-8b-instruct`
**Integration point:** `src/pipeline/bluf.py`

---

## Tech Stack

| Layer | Technology |
|---|---|
| Orchestration | LangGraph 0.2+ |
| Embedding / Correlation | sentence-transformers + FAISS |
| Classification | scikit-learn RandomForestClassifier |
| ATT&CK Mapping | MITRE ATT&CK STIX JSON (mitreattack-python) |
| LLM / IBM Bob | ibm-watsonx-ai (Granite-3) |
| Storage | SQLAlchemy + SQLite |
| Dashboard | Streamlit + Plotly |
| Schema | Pydantic v2 |

---

## Repository Structure

```
submission.yaml          ← Hackathon submission manifest
README.md
requirements.txt
.env.example             ← Environment variable template
src/
  schema.py              ← Pydantic data models
  db.py                  ← SQLAlchemy/SQLite persistence
  run_pipeline.py        ← CLI entry point
  app.py                 ← Streamlit dashboard
  data/
    generate_alerts.py   ← Seeded synthetic alert generator
  pipeline/
    graph.py             ← LangGraph StateGraph
    ingest.py            ← Stage 1: multi-source parsing
    correlate.py         ← Stage 2: FAISS clustering
    classify.py          ← Stage 3: RandomForest scoring
    map_attack.py        ← Stage 4: ATT&CK mapping
    bluf.py              ← Stage 5: IBM watsonx BLUF
docs/
  problem-statement.md
  solution-overview.md
  architecture.md
  setup-guide.md
demo/
  demo-video-link.txt
  live-demo-url.txt
  screenshots/
presentation/
  outline.md
```

---

## Documentation

- [Problem Statement](docs/problem-statement.md) — D2 challenge context and requirements
- [Solution Overview](docs/solution-overview.md) — How each component addresses the problem
- [Architecture](docs/architecture.md) — Full Mermaid diagram and component table
- [Setup Guide](docs/setup-guide.md) — Complete installation and verification guide

---

## Demo

- **Video:** [demo/demo-video-link.txt](demo/demo-video-link.txt)
- **Live URL:** [demo/live-demo-url.txt](demo/live-demo-url.txt)
- **Screenshots:** [demo/screenshots/](demo/screenshots/)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Team

**ThreatLens AI** — Bob AI Hackathon 2024
Built with IBM watsonx, LangGraph, sentence-transformers, FAISS, and MITRE ATT&CK.
