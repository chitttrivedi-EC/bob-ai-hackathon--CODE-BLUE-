"""
app.py — ThreatLens AI Streamlit Dashboard.

4-tab interface:
  Tab 1 — Raw Alerts      : table of all ingested alerts with severity badges
  Tab 2 — Correlated Clusters : cluster view showing cross-source linking
  Tab 3 — Priority Queue  : ranked by threat_score, FP badges
  Tab 4 — BLUF Briefs     : structured IBM Granite-3 generated briefs

Run: streamlit run src/app.py
"""
from __future__ import annotations

import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()

# ── Page config (MUST be first Streamlit call) ────────────────────────────────

st.set_page_config(
    page_title="ThreatLens AI — Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* Dark theme overrides */
:root {
    --bg-primary:   #0d1117;
    --bg-secondary: #161b22;
    --bg-card:      #1c2128;
    --border:       #30363d;
    --accent:       #58a6ff;
    --success:      #3fb950;
    --warning:      #d29922;
    --danger:       #f85149;
    --critical:     #ff4040;
    --text-primary: #e6edf3;
    --text-muted:   #8b949e;
}

.main { background-color: var(--bg-primary); }

/* Severity badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}
.badge-critical { background:#ff4040; color:#fff; }
.badge-high     { background:#d29922; color:#000; }
.badge-medium   { background:#388bfd; color:#fff; }
.badge-low      { background:#3fb950; color:#000; }
.badge-info     { background:#8b949e; color:#fff; }
.badge-fp       { background:#6e40c9; color:#fff; }

/* Source type chips */
.chip {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.68rem;
    font-weight: 600;
    margin: 2px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    color: var(--accent);
}

/* BLUF card */
.bluf-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 16px;
}
.bluf-section-label {
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 2px;
}
.bluf-bottom-line {
    font-size: 1.05rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 12px;
}
.bluf-body {
    font-size: 0.88rem;
    color: var(--text-primary);
    line-height: 1.55;
}
.classification-banner {
    background: #1a1200;
    border: 1px solid #d29922;
    color: #d29922;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-align: center;
    margin-bottom: 12px;
}
.technique-chip {
    display: inline-block;
    background: #1f2937;
    border: 1px solid #374151;
    color: #60a5fa;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.72rem;
    font-family: monospace;
    margin: 2px;
}
.metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}
.metric-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
}
.metric-label {
    font-size: 0.78rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.threat-bar-container {
    background: #1c2128;
    border-radius: 4px;
    height: 8px;
    width: 100%;
}
.threat-bar {
    height: 8px;
    border-radius: 4px;
}
</style>
""", unsafe_allow_html=True)


# ── DB helpers ────────────────────────────────────────────────────────────────

@st.cache_data(ttl=5)
def load_alerts():
    try:
        from src.db import get_session, load_all_alerts, init_db
        init_db()
        with get_session() as s:
            rows = load_all_alerts(s)
        return [
            {
                "id":                r.id,
                "source_type":       r.source_type,
                "severity":          r.severity,
                "timestamp":         str(r.timestamp),
                "raw_text":          r.raw_text,
                "source_ip":         r.source_ip or "",
                "dest_ip":           r.dest_ip or "",
                "event_type":        r.event_type or "",
                "actor":             r.actor or "",
                "cve_ids":           json.loads(str(r.cve_ids or "[]")),
                "confidence":        r.confidence or 1.0,
                "is_false_positive": r.is_false_positive,
                "cluster_id":        r.cluster_id or "",
                "threat_score":      r.threat_score or 0.0,
            }
            for r in rows
        ]
    except Exception:
        return []


@st.cache_data(ttl=5)
def load_clusters():
    try:
        from src.db import get_session, load_all_clusters, init_db
        init_db()
        with get_session() as s:
            rows = load_all_clusters(s)
        result = []
        for r in rows:
            bluf_data = None
            raw_bluf = getattr(r, "bluf_json", None)
            if raw_bluf:
                try:
                    bluf_data = json.loads(str(raw_bluf))
                except Exception:
                    pass
            result.append({
                "cluster_id":        r.cluster_id,
                "alert_ids":         json.loads(str(r.alert_ids or "[]")),
                "source_types":      json.loads(str(r.source_types or "[]")),
                "max_severity":      r.max_severity or "medium",
                "avg_similarity":    r.avg_similarity or 0.0,
                "combined_text":     r.combined_text or "",
                "alert_count":       r.alert_count or 1,
                "threat_score":      r.threat_score or 0.0,
                "is_false_positive": r.is_false_positive,
                "attack_techniques": json.loads(str(r.attack_techniques or "[]")),
                "bluf":              bluf_data,
            })
        return result
    except Exception:
        return []


# ── UI Helpers ────────────────────────────────────────────────────────────────

_SEV_COLORS = {
    "critical": "#ff4040",
    "high":     "#d29922",
    "medium":   "#388bfd",
    "low":      "#3fb950",
    "info":     "#8b949e",
}

def sev_badge(severity: str) -> str:
    cls = f"badge-{severity.lower()}"
    return f'<span class="badge {cls}">{severity.upper()}</span>'

def source_chip(source_type: str) -> str:
    label = source_type.replace("_", " ").title()
    return f'<span class="chip">{label}</span>'

def threat_bar_html(score: float, is_fp: bool) -> str:
    color = "#6e40c9" if is_fp else (
        "#ff4040" if score > 0.8 else
        "#d29922" if score > 0.5 else
        "#388bfd"
    )
    pct = int(score * 100)
    return f"""
    <div class="threat-bar-container">
      <div class="threat-bar" style="width:{pct}%; background:{color};"></div>
    </div>
    <small style="color:#8b949e;">{pct}%</small>
    """


# ── Header ────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="text-align:center; padding: 24px 0 8px 0;">
  <h1 style="font-size:2.2rem; font-weight:800; color:#e6edf3; margin:0;">
    🛡️ ThreatLens AI
  </h1>
  <p style="color:#8b949e; font-size:0.95rem; margin-top:4px;">
    Threat Intelligence Correlation &amp; Alert Prioritisation — Bob AI Hackathon D2
  </p>
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ Pipeline Control")

    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("### 🔗 Run Pipeline")
    input_file = st.text_input("Alert JSON file", value="data/synthetic_alerts.json")
    reset_db   = st.checkbox("Reset database", value=False)

    if st.button("▶ Run Pipeline", use_container_width=True, type="primary"):
        with st.spinner("Running ThreatLens pipeline…"):
            import subprocess
            cmd = [sys.executable, "src/run_pipeline.py", "--input", input_file]
            if reset_db:
                cmd.append("--reset-db")
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
        if result.returncode == 0:
            st.success("Pipeline completed successfully!")
        else:
            st.error("Pipeline encountered errors")
        with st.expander("Pipeline output"):
            st.code(result.stdout + result.stderr)
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("### 🤖 IBM Bob Status")
    watsonx_key = os.getenv("WATSONX_API_KEY", "")
    if watsonx_key and not watsonx_key.startswith("your_"):
        st.success("✅ watsonx.ai connected")
        st.caption(f"Model: {os.getenv('WATSONX_MODEL_ID','ibm/granite-3-8b-instruct')}")
    else:
        st.warning("⚠️ watsonx credentials not set")
        st.caption("BLUFs generated from template fallback")

    st.divider()
    st.markdown("### 📂 Quick Start")
    st.code(
        "python src/data/generate_alerts.py \\\n"
        "  --seed 42 \\\n"
        "  --output data/synthetic_alerts.json",
        language="bash"
    )


# ── Load data ─────────────────────────────────────────────────────────────────

alerts   = load_alerts()
clusters = load_clusters()

# ── KPI metrics ───────────────────────────────────────────────────────────────

true_clusters  = [c for c in clusters if not c.get("is_false_positive")]
fp_clusters    = [c for c in clusters if c.get("is_false_positive")]
cross_src      = [c for c in clusters if len(c.get("source_types", [])) > 1]
critical_count = sum(1 for c in true_clusters if c.get("max_severity") == "critical")
briefs_count   = sum(1 for c in clusters if c.get("bluf"))

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Alerts",    len(alerts),       delta=None)
with col2:
    st.metric("Threat Clusters", len(true_clusters), delta=None)
with col3:
    st.metric("False Positives", len(fp_clusters),   delta=None)
with col4:
    st.metric("Cross-Source",    len(cross_src),     delta=None)
with col5:
    st.metric("BLUF Briefs",     briefs_count,        delta=None)

st.divider()

# ── No data state ─────────────────────────────────────────────────────────────

if not alerts and not clusters:
    st.info(
        "📭 **No data yet.** Run the pipeline to populate the dashboard:\n\n"
        "```bash\n"
        "python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json\n"
        "python src/run_pipeline.py --input data/synthetic_alerts.json\n"
        "```\n\n"
        "Or use the **Run Pipeline** button in the sidebar."
    )
    st.stop()


# ── TABS ──────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs([
    "📥 Raw Alerts",
    "🔗 Correlated Clusters",
    "⚡ Priority Queue",
    "📋 BLUF Briefs",
])


# ────────────────────────────────────────────────────────────────────────────
# TAB 1 — RAW ALERTS
# ────────────────────────────────────────────────────────────────────────────

with tab1:
    st.subheader("Raw Ingested Alerts")

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        source_filter = st.multiselect(
            "Source Type",
            ["siem", "satellite", "cyber_sensor", "intel_report"],
            default=[],
            key="tab1_src",
        )
    with col_f2:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low", "info"],
            default=[],
            key="tab1_sev",
        )
    with col_f3:
        fp_filter = st.selectbox(
            "Alert Type",
            ["All", "True Positive", "False Positive"],
            key="tab1_fp",
        )

    # Filter logic
    filtered = alerts
    if source_filter:
        filtered = [a for a in filtered if a["source_type"] in source_filter]
    if sev_filter:
        filtered = [a for a in filtered if a["severity"] in sev_filter]
    if fp_filter == "True Positive":
        filtered = [a for a in filtered if not a["is_false_positive"]]
    elif fp_filter == "False Positive":
        filtered = [a for a in filtered if a["is_false_positive"]]

    st.caption(f"Showing {len(filtered)} of {len(alerts)} alerts")

    # Source type distribution chart
    if alerts:
        src_counts = {}
        for a in alerts:
            src_counts[a["source_type"].replace("_", " ").title()] = \
                src_counts.get(a["source_type"].replace("_", " ").title(), 0) + 1
        fig = px.bar(
            x=list(src_counts.keys()),
            y=list(src_counts.values()),
            color=list(src_counts.keys()),
            color_discrete_map={
                "Siem":          "#388bfd",
                "Satellite":     "#3fb950",
                "Cyber Sensor":  "#d29922",
                "Intel Report":  "#f85149",
            },
            labels={"x": "Source Type", "y": "Alert Count"},
            title="Alerts by Source Type",
            height=220,
        )
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#e6edf3", showlegend=False,
            margin=dict(l=0, r=0, t=30, b=0),
        )
        fig.update_xaxes(gridcolor="#30363d")
        fig.update_yaxes(gridcolor="#30363d")
        st.plotly_chart(fig, use_container_width=True)

    # Alert table
    if filtered:
        rows_html = ""
        for a in filtered[:200]:
            sev  = a["severity"]
            fp   = a.get("is_false_positive")
            badge = sev_badge(sev)
            fp_badge = '<span class="badge badge-fp">FP</span>' if fp else ""
            src_c = source_chip(a["source_type"])
            text  = a["raw_text"][:120] + "…" if len(a["raw_text"]) > 120 else a["raw_text"]
            rows_html += f"""
            <tr>
              <td>{a['timestamp'][:16]}</td>
              <td>{src_c}</td>
              <td>{badge} {fp_badge}</td>
              <td style="max-width:400px; white-space:normal;">{text}</td>
              <td>{a['source_ip'] or '—'}</td>
              <td>{a['actor'] or '—'}</td>
            </tr>
            """
        st.markdown(f"""
        <table style="width:100%; border-collapse:collapse; font-size:0.82rem; color:#e6edf3;">
          <thead>
            <tr style="background:#161b22; color:#8b949e; text-transform:uppercase; font-size:0.7rem;">
              <th style="padding:8px;text-align:left;">Timestamp</th>
              <th style="padding:8px;text-align:left;">Source</th>
              <th style="padding:8px;text-align:left;">Severity</th>
              <th style="padding:8px;text-align:left;">Summary</th>
              <th style="padding:8px;text-align:left;">Source IP</th>
              <th style="padding:8px;text-align:left;">Actor</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
        """, unsafe_allow_html=True)
    else:
        st.info("No alerts match the selected filters.")


# ────────────────────────────────────────────────────────────────────────────
# TAB 2 — CORRELATED CLUSTERS
# ────────────────────────────────────────────────────────────────────────────

with tab2:
    st.subheader("Correlated Alert Clusters")
    st.caption(
        "Alerts describing the same underlying incident are grouped by semantic "
        "similarity (sentence-transformers + FAISS). Cross-source clusters "
        "strengthen confidence."
    )

    # Similarity distribution
    if clusters:
        sims = [c["avg_similarity"] for c in clusters if c["avg_similarity"] > 0]
        if sims:
            fig2 = px.histogram(
                sims, nbins=20,
                title="Cluster Intra-Similarity Distribution",
                labels={"value": "Avg Cosine Similarity", "count": "Clusters"},
                height=200,
                color_discrete_sequence=["#388bfd"],
            )
            fig2.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                font_color="#e6edf3", showlegend=False,
                margin=dict(l=0, r=0, t=30, b=0),
            )
            fig2.update_xaxes(gridcolor="#30363d")
            fig2.update_yaxes(gridcolor="#30363d")
            st.plotly_chart(fig2, use_container_width=True)

    # Cross-source filter
    show_cross_only = st.checkbox("Show cross-source clusters only", value=False)
    display_clusters = [c for c in clusters if len(c["source_types"]) > 1] \
                       if show_cross_only else clusters

    st.caption(f"Showing {len(display_clusters)} clusters")

    for cluster in display_clusters[:50]:
        is_fp  = cluster.get("is_false_positive", False)
        sev    = cluster.get("max_severity", "medium")
        score  = cluster.get("threat_score", 0.0)
        srcs   = cluster.get("source_types", [])
        cnt    = cluster.get("alert_count", 1)
        sim    = cluster.get("avg_similarity", 0.0)
        cid    = cluster["cluster_id"][:8]

        label  = "⚠️ FALSE POSITIVE" if is_fp else f"🔴 THREAT — {sev.upper()}"
        color  = "#6e40c9" if is_fp else _SEV_COLORS.get(sev, "#388bfd")

        with st.expander(
            f"{label} | {cnt} alert(s) | {len(srcs)} source(s) | "
            f"sim={sim:.2f} | ID:{cid}"
        ):
            col_a, col_b = st.columns([2, 1])
            with col_a:
                chips = " ".join(source_chip(s) for s in srcs)
                st.markdown(f"**Sources:** {chips}", unsafe_allow_html=True)
                st.markdown(f"**Threat Score:** {int(score*100)}%")
                st.markdown(f"**Alerts in cluster:** {cnt}")
            with col_b:
                st.markdown(threat_bar_html(score, is_fp), unsafe_allow_html=True)

            if cluster.get("attack_techniques"):
                techs_html = " ".join(
                    f'<span class="technique-chip">{t["technique_id"]} {t["name"]}</span>'
                    for t in cluster["attack_techniques"]
                )
                st.markdown(f"**ATT&CK:** {techs_html}", unsafe_allow_html=True)

            with st.expander("Combined alert text"):
                st.text(cluster.get("combined_text", "")[:600])


# ────────────────────────────────────────────────────────────────────────────
# TAB 3 — PRIORITY QUEUE
# ────────────────────────────────────────────────────────────────────────────

with tab3:
    st.subheader("⚡ Threat Priority Queue")
    st.caption(
        "Clusters ranked by RandomForest threat score (descending). "
        "False-positive clusters are shown at the bottom."
    )

    sorted_clusters = sorted(
        clusters,
        key=lambda c: (
            0 if c.get("is_false_positive") else 1,
            c.get("threat_score", 0)
        ),
        reverse=True,
    )

    # Threat score scatter
    if sorted_clusters:
        df_scores = pd.DataFrame([
            {
                "Cluster": f"#{i+1}",
                "Threat Score": c.get("threat_score", 0),
                "Severity": c.get("max_severity", "medium").title(),
                "Alerts": c.get("alert_count", 1),
                "FP": c.get("is_false_positive", False),
                "Sources": len(c.get("source_types", [])),
            }
            for i, c in enumerate(sorted_clusters)
        ])
        fig3 = px.scatter(
            df_scores,
            x="Cluster", y="Threat Score",
            color="Severity",
            size="Alerts",
            symbol="FP",
            color_discrete_map={
                "Critical": "#ff4040",
                "High":     "#d29922",
                "Medium":   "#388bfd",
                "Low":      "#3fb950",
                "Info":     "#8b949e",
            },
            title="Threat Score by Cluster",
            height=280,
        )
        fig3.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font_color="#e6edf3",
            margin=dict(l=0, r=0, t=30, b=0),
        )
        fig3.update_xaxes(gridcolor="#30363d")
        fig3.update_yaxes(gridcolor="#30363d", range=[0, 1.05])
        fig3.add_hline(y=0.35, line_dash="dash", line_color="#6e40c9",
                       annotation_text="FP threshold (0.35)")
        st.plotly_chart(fig3, use_container_width=True)

    # Priority list
    for rank, cluster in enumerate(sorted_clusters[:30], 1):
        is_fp  = cluster.get("is_false_positive", False)
        sev    = cluster.get("max_severity", "medium")
        score  = cluster.get("threat_score", 0.0)
        srcs   = cluster.get("source_types", [])
        cnt    = cluster.get("alert_count", 1)
        techs  = cluster.get("attack_techniques", [])

        bg     = "#1a0a0a" if (not is_fp and sev in ("critical","high")) else "#1c2128"
        border = _SEV_COLORS.get(sev, "#30363d") if not is_fp else "#6e40c9"

        badge_html  = sev_badge(sev)
        fp_html     = '<span class="badge badge-fp" style="margin-left:6px;">FALSE POSITIVE</span>' if is_fp else ""
        source_html = " ".join(source_chip(s) for s in srcs)
        tech_html   = " ".join(
            f'<span class="technique-chip">{t["technique_id"]}</span>'
            for t in techs[:3]
        )
        score_pct = int(score * 100)
        bar_color = "#6e40c9" if is_fp else _SEV_COLORS.get(sev, "#388bfd")

        st.markdown(f"""
        <div style="background:{bg}; border:1px solid {border};
                    border-radius:8px; padding:14px 16px; margin-bottom:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
              <span style="font-size:1.1rem; font-weight:700; color:#e6edf3;">
                #{rank}
              </span>
              &nbsp;{badge_html}{fp_html}
              &nbsp;<span style="color:#8b949e; font-size:0.8rem;">
                {cnt} alert(s) · {len(srcs)} source(s)
              </span>
            </div>
            <div style="text-align:right;">
              <span style="font-size:1.4rem; font-weight:800; color:{bar_color};">
                {score_pct}%
              </span>
              <span style="color:#8b949e; font-size:0.72rem; margin-left:4px;">
                threat score
              </span>
            </div>
          </div>
          <div style="margin-top:8px;">{source_html}</div>
          {f'<div style="margin-top:6px;">{tech_html}</div>' if tech_html else ''}
          <div style="margin-top:8px; background:#161b22; border-radius:4px; height:6px;">
            <div style="width:{score_pct}%; height:6px; border-radius:4px;
                        background:{bar_color};"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────────────
# TAB 4 — BLUF BRIEFS
# ────────────────────────────────────────────────────────────────────────────

with tab4:
    st.subheader("📋 BLUF Intelligence Briefs")

    watsonx_key = os.getenv("WATSONX_API_KEY", "")
    if watsonx_key and not watsonx_key.startswith("your_"):
        st.success("🤖 Briefs generated by **IBM watsonx Granite-3** (ibm/granite-3-8b-instruct)")
    else:
        st.info("ℹ️ Running in fallback mode — briefs are template-generated. "
                "Set WATSONX_API_KEY and WATSONX_PROJECT_ID for live IBM Granite output.")

    # Get clusters with BLUFs
    clusters_with_bluf = [
        c for c in clusters
        if c.get("bluf") and not c.get("is_false_positive")
    ]
    # Sort by threat score
    clusters_with_bluf.sort(
        key=lambda c: c.get("threat_score", 0), reverse=True
    )

    if not clusters_with_bluf:
        st.info("No BLUF briefs yet. Run the pipeline first.")
        st.stop()

    st.caption(f"{len(clusters_with_bluf)} BLUF brief(s) generated")

    for cluster in clusters_with_bluf:
        bluf  = cluster["bluf"]
        sev   = cluster.get("max_severity", "medium")
        score = cluster.get("threat_score", 0.0)
        srcs  = cluster.get("source_types", [])
        techs = cluster.get("attack_techniques", [])

        confidence = bluf.get("confidence", "MEDIUM")
        conf_color = {
            "HIGH":   "#ff4040",
            "MEDIUM": "#d29922",
            "LOW":    "#3fb950",
        }.get(confidence.upper(), "#388bfd")

        tech_chips = " ".join(
            f'<span class="technique-chip">{t["technique_id"]} — {t["name"]}</span>'
            for t in techs
        )
        source_chips = " ".join(source_chip(s) for s in srcs)
        is_fallback  = bluf.get("is_fallback", True)
        gen_by = bluf.get("generated_by", "Unknown")

        st.markdown(f"""
        <div class="bluf-card">
          <div class="classification-banner">{bluf.get('classification','UNCLASSIFIED')}</div>

          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
            <div>
              {sev_badge(sev)}
              <span style="margin-left:8px; font-size:0.78rem; color:#8b949e;">
                Threat Score: <strong style="color:{conf_color};">{int(score*100)}%</strong>
              </span>
              <span style="margin-left:12px; font-size:0.78rem; color:#8b949e;">
                Confidence: <strong style="color:{conf_color};">{confidence}</strong>
              </span>
            </div>
            <span style="font-size:0.68rem; color:#8b949e;">
              {'⚠️ Template fallback' if is_fallback else '🤖 IBM Granite-3'}
            </span>
          </div>

          <div class="bluf-section-label">Bottom Line</div>
          <div class="bluf-bottom-line">{bluf.get('bottom_line','')}</div>

          <div class="bluf-section-label">Supporting Detail</div>
          <div class="bluf-body" style="margin-bottom:10px;">
            {bluf.get('supporting_detail','')}
          </div>

          <div class="bluf-section-label">ATT&amp;CK Techniques</div>
          <div style="margin-bottom:10px;">
            {tech_chips if tech_chips else '<span style="color:#8b949e; font-size:0.82rem;">None identified</span>'}
          </div>

          <div class="bluf-section-label">Techniques Assessment</div>
          <div class="bluf-body" style="margin-bottom:10px;">
            {bluf.get('techniques_summary','')}
          </div>

          <div class="bluf-section-label" style="color:#d29922;">Recommended Action</div>
          <div class="bluf-body" style="color:#ffd700; font-weight:600; margin-bottom:10px;">
            ➤ {bluf.get('recommended_action','')}
          </div>

          <div style="margin-top:8px; padding-top:8px; border-top:1px solid #30363d;">
            <span style="font-size:0.68rem; color:#8b949e;">Sources: {source_chips}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Download briefs as JSON ────────────────────────────────────────────
    briefs_export = [c["bluf"] for c in clusters_with_bluf if c.get("bluf")]
    if briefs_export:
        st.download_button(
            label="⬇ Download All BLUF Briefs (JSON)",
            data=json.dumps(briefs_export, indent=2, default=str),
            file_name="bluf_briefs.json",
            mime="application/json",
        )


# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<p style='text-align:center; color:#8b949e; font-size:0.75rem;'>"
    "ThreatLens AI — Bob AI Hackathon D2 | Defense &amp; Aerospace Track | "
    "Powered by IBM watsonx Granite-3, LangGraph, sentence-transformers, FAISS, MITRE ATT&amp;CK"
    "</p>",
    unsafe_allow_html=True,
)
