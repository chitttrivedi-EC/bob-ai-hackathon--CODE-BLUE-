# Setup Guide — ThreatLens AI

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Tested on 3.11 and 3.12 |
| pip | 23+ | `pip install --upgrade pip` |
| Git | Any | For cloning the repo |
| Internet access | Required | One-time ATT&CK STIX download + optional watsonx calls |
| RAM | ≥ 4 GB | sentence-transformers model is ~80 MB; FAISS index is in-memory |
| IBM Cloud account | Optional | Required only for live watsonx BLUF generation |

---

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/threat-intelligence-d2.git
cd threat-intelligence-d2
```

---

## 2. Create and Activate a Virtual Environment

```bash
# Create
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1
```

---

## 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note:** The first install downloads `sentence-transformers/all-MiniLM-L6-v2` (~80 MB). This is a one-time network operation.

---

## 4. Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` in a text editor and fill in the values:

```dotenv
# Required for live IBM Granite-3 BLUF generation
WATSONX_API_KEY=<your IBM Cloud API key>
WATSONX_PROJECT_ID=<your watsonx project ID>
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL_ID=ibm/granite-3-8b-instruct

# Optional tuning (defaults shown)
CORRELATION_THRESHOLD=0.75
DB_PATH=data/threatintel.db
ATTACK_STIX_PATH=data/attack_stix.json
```

### Getting IBM Cloud Credentials

1. Go to [https://cloud.ibm.com/iam/apikeys](https://cloud.ibm.com/iam/apikeys)
2. Create a new API key, copy the value → `WATSONX_API_KEY`
3. Open [https://us-south.ml.cloud.ibm.com/projects/](https://us-south.ml.cloud.ibm.com/projects/)
4. Open your project → Settings → General → copy the Project ID → `WATSONX_PROJECT_ID`

> **Without credentials:** The pipeline still runs fully. BLUF briefs are generated from a structured template rather than IBM Granite-3. This is clearly indicated in the UI with a `⚠️ Template fallback` label.

---

## 5. Generate Synthetic Alert Data

```bash
python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json
```

**Expected output:**
```
[generator] seed=42  count=200  output=data/synthetic_alerts.json
[generator] Generated 200 alerts:
            True positives : 159
            False positives: 41
            By source type : {'siem': 51, 'satellite': 49, 'cyber_sensor': 52, 'intel_report': 48}
[generator] Saved → data/synthetic_alerts.json
```

---

## 6. Run the Full Pipeline

```bash
python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
```

**What you should see:**
```
████████████████████████████████████████████████████████████
  ThreatLens AI — Threat Intelligence Pipeline
  Started: 2024-09-01 12:00:00
████████████████████████████████████████████████████████████

============================================================
  STAGE 1 / 5 — INGEST & NORMALISE
============================================================
[ingest] Loading alerts from data/synthetic_alerts.json
[ingest] Parsed 200 alerts | errors=0
...

============================================================
  STAGE 2 / 5 — SEMANTIC CORRELATION (FAISS)
============================================================
[correlate] Embedding 200 alerts with sentence-transformers...
[correlate] FAISS index built: 200 vectors, dim=384
[correlate] Clustering with threshold=0.75...
[correlate] Formed N clusters from 200 alerts
[correlate] Cross-source clusters: X/N
...

============================================================
  STAGE 3 / 5 — THREAT CLASSIFICATION (RandomForest)
============================================================
...

============================================================
  STAGE 4 / 5 — MITRE ATT&CK MAPPING
============================================================
[map_attack] Downloading ATT&CK STIX dataset (one-time)...
...

============================================================
  STAGE 5 / 5 — BLUF GENERATION (IBM watsonx Granite-3)
============================================================
[bluf] IBM watsonx ENABLED  ← (or DISABLED if no credentials)
...

============================================================
  PIPELINE COMPLETE
============================================================
  Alerts ingested    : 200
  Clusters formed    : N
  ├─ True threats    : X
  ├─ False positives : Y
  └─ Cross-source    : Z
  BLUF briefs        : X
  Errors             : 0

  VERIFICATION:
  ✓ Cross-source correlation : PASS (Z clusters)
  ✓ FP classifier scoring    : PASS
  ✓ BLUF briefs well-formed  : PASS (X briefs)

  Launch dashboard: streamlit run src/app.py
```

> **First run note:** The MITRE ATT&CK STIX download is ~60 MB and takes 30–60 seconds on a typical connection. It's cached to `data/attack_stix.json` and not re-downloaded on subsequent runs.

---

## 7. Launch the Streamlit Dashboard

```bash
streamlit run src/app.py
```

Open your browser to **[http://localhost:8501](http://localhost:8501)**.

You should see the ThreatLens AI dashboard with four tabs:
1. **Raw Alerts** — 200 alerts with severity badges and source-type filters
2. **Correlated Clusters** — grouped alerts with similarity scores
3. **Priority Queue** — ranked by threat score with visual score bars
4. **BLUF Briefs** — formatted intelligence cards

---

## 8. Verification Checklist

After running the pipeline, verify:

- [ ] `data/synthetic_alerts.json` exists and contains 200 entries
- [ ] `data/threatintel.db` exists (SQLite database)
- [ ] `data/attack_stix.json` exists (~60 MB)
- [ ] `data/classifier_model.joblib` exists (trained model)
- [ ] Pipeline output shows `PASS` for all 3 verification checks
- [ ] Streamlit dashboard loads at `http://localhost:8501`
- [ ] Raw Alerts tab shows all 4 source types (SIEM, Satellite, Cyber Sensor, Intel Report)
- [ ] Correlated Clusters tab shows at least 1 cross-source cluster
- [ ] BLUF Briefs tab shows formatted cards

---

## Re-Running the Pipeline

To re-run with fresh data and a reset database:

```bash
python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json
python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
```

To use a different seed for different synthetic data:

```bash
python src/data/generate_alerts.py --seed 123 --count 500 --output data/synthetic_alerts.json
python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'sentence_transformers'` | Dependencies not installed | `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'faiss'` | FAISS not installed | `pip install faiss-cpu` |
| STIX download hangs / fails | Slow network or MITRE rate-limit | Re-run; uses fallback technique list if download fails |
| `BLUF generation: watsonx call failed` | Invalid credentials | Check `WATSONX_API_KEY` and `WATSONX_PROJECT_ID` in `.env` |
| `Cross-source correlation : FAIL` | Threshold too high | Lower `CORRELATION_THRESHOLD` in `.env` (try 0.65) |
| Streamlit shows "No data yet" | Pipeline hasn't run | Run `python src/run_pipeline.py ...` first |
| `OperationalError: database is locked` | Stale SQLite lock | Delete `data/threatintel.db` and re-run with `--reset-db` |
| `classifier_model.joblib` loading error | Model version mismatch | Re-run pipeline; model is retrained automatically |
| `Permission denied` on Windows | OneDrive sync conflict | Pause OneDrive sync, then re-run |
| Streamlit port already in use | Another process on 8501 | `streamlit run src/app.py --server.port 8502` |

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `WATSONX_API_KEY` | No* | — | IBM Cloud API key (*required for live BLUF) |
| `WATSONX_PROJECT_ID` | No* | — | watsonx.ai project ID |
| `WATSONX_URL` | No | `https://us-south.ml.cloud.ibm.com` | Regional API endpoint |
| `WATSONX_MODEL_ID` | No | `ibm/granite-3-8b-instruct` | Granite model variant |
| `CORRELATION_THRESHOLD` | No | `0.75` | Cosine similarity threshold for clustering |
| `DB_PATH` | No | `data/threatintel.db` | SQLite database path |
| `ATTACK_STIX_PATH` | No | `data/attack_stix.json` | ATT&CK STIX cache path |
| `CLASSIFIER_MODEL_PATH` | No | `data/classifier_model.joblib` | Trained classifier path |

---

## Directory Structure After Setup

```
threat-intelligence-d2/
├── .env                          ← your credentials (not committed)
├── .env.example                  ← template
├── requirements.txt
├── submission.yaml
├── README.md
├── data/
│   ├── synthetic_alerts.json     ← generated alert data
│   ├── threatintel.db            ← SQLite database
│   ├── attack_stix.json          ← MITRE ATT&CK cache (~60 MB)
│   └── classifier_model.joblib   ← trained RandomForest model
├── src/
│   ├── schema.py
│   ├── db.py
│   ├── run_pipeline.py
│   ├── app.py
│   ├── data/
│   │   └── generate_alerts.py
│   └── pipeline/
│       ├── __init__.py
│       ├── ingest.py
│       ├── correlate.py
│       ├── classify.py
│       ├── map_attack.py
│       ├── bluf.py
│       └── graph.py
└── docs/
    ├── problem-statement.md
    ├── solution-overview.md
    ├── architecture.md
    └── setup-guide.md
```
