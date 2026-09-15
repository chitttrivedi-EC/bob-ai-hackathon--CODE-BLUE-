"""
correlate.py — Semantic alert correlation stage.

Uses sentence-transformers (all-MiniLM-L6-v2) to embed alert raw_text,
then builds a FAISS index for fast approximate nearest-neighbour search.
Alerts with cosine similarity above CORRELATION_THRESHOLD are grouped
into AlertCluster objects.

Algorithm:
  1. Embed all alert texts (batch, GPU if available)
  2. Build FAISS IndexFlatIP (inner product = cosine on normalised vectors)
  3. Union-Find grouping: for each alert, link all neighbours within threshold
  4. Assign cluster_id back to NormalizedAlert rows in SQLite

LangGraph node: correlate_node(state) -> state
"""
from __future__ import annotations

import os
import sys
from typing import Dict, List

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.schema import (
    AlertCluster, NormalizedAlert, SeverityLevel
)
from src.db import get_session, upsert_cluster

# Severity ordering for max_severity calculation
_SEV_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH:     4,
    SeverityLevel.MEDIUM:   3,
    SeverityLevel.LOW:      2,
    SeverityLevel.INFO:     1,
}

THRESHOLD = float(os.getenv("CORRELATION_THRESHOLD", "0.65"))


def share_indicators(a: NormalizedAlert, b: NormalizedAlert) -> bool:
    """Check if two alerts share key technical indicators (IPs, CVEs, Threat Actors)."""
    # Shared source IP (external attacker infrastructure)
    if a.source_ip and b.source_ip and a.source_ip == b.source_ip:
        return True
    # Shared destination IP with matching CVE or Actor
    if a.dest_ip and b.dest_ip and a.dest_ip == b.dest_ip:
        if (a.actor and b.actor and a.actor == b.actor and a.actor not in ("Unknown", "N/A")) or \
           (a.cve_ids and b.cve_ids and set(a.cve_ids) & set(b.cve_ids)):
            return True
    # Shared CVE and Actor
    if a.cve_ids and b.cve_ids and set(a.cve_ids) & set(b.cve_ids):
        if a.actor and b.actor and a.actor == b.actor and a.actor not in ("Unknown", "N/A"):
            return True
    return False


# ── Union-Find ────────────────────────────────────────────────────────────────

class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank   = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int):
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def groups(self) -> Dict[int, List[int]]:
        result: Dict[int, List[int]] = {}
        for i in range(len(self.parent)):
            root = self.find(i)
            result.setdefault(root, []).append(i)
        return result


# ── Main correlation function ─────────────────────────────────────────────────

def correlate_alerts(alerts: List[NormalizedAlert]) -> List[AlertCluster]:
    """
    Embed alerts with sentence-transformers, cluster via FAISS + Union-Find,
    write clusters to SQLite, return AlertCluster list.
    """
    if not alerts:
        return []

    print(f"[correlate] Embedding {len(alerts)} alerts with sentence-transformers...")

    # Lazy import to avoid slow load on import
    from sentence_transformers import SentenceTransformer
    import faiss

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    texts = [a.raw_text for a in alerts]
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=False,
        normalize_embeddings=True,    # L2-normalise → cosine similarity = inner product
        convert_to_numpy=True,
    ).astype("float32")

    # Store embeddings back on alert objects (in-memory only)
    for alert, emb in zip(alerts, embeddings):
        alert.embedding = emb.tolist()

    n = len(alerts)
    dim = embeddings.shape[1]

    # FAISS IndexFlatIP for exact cosine similarity on normalised vectors
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    print(f"[correlate] FAISS index built: {n} vectors, dim={dim}")
    print(f"[correlate] Clustering with threshold={THRESHOLD}...")

    uf = UnionFind(n)

    # Search each alert for neighbours; k = min(10, n)
    k = min(20, n)
    D, I = index.search(embeddings, k)

    for i in range(n):
        for j_idx in range(k):
            j    = int(I[i, j_idx])
            sim  = float(D[i, j_idx])
            if j == i:
                continue
            if sim >= THRESHOLD:
                uf.union(i, j)

    # Indicator correlation (shared IP / CVE / Actor across sources)
    for i in range(n):
        for j in range(i + 1, n):
            if share_indicators(alerts[i], alerts[j]):
                uf.union(i, j)

    groups = uf.groups()
    print(f"[correlate] Formed {len(groups)} clusters from {n} alerts")

    clusters: List[AlertCluster] = []

    with get_session() as session:
        for _, member_indices in groups.items():
            member_alerts = [alerts[i] for i in member_indices]

            # Compute cluster metadata
            max_sev = max(member_alerts, key=lambda a: _SEV_ORDER[a.severity]).severity
            source_types = list({a.source_type for a in member_alerts})
            combined_text = " ".join(
                a.raw_text for a in member_alerts
            )[:2000]

            # Average pairwise similarity within cluster
            if len(member_indices) > 1:
                embs = embeddings[member_indices]
                sim_matrix = embs @ embs.T
                mask = np.ones_like(sim_matrix, dtype=bool)
                np.fill_diagonal(mask, False)
                avg_sim = float(sim_matrix[mask].mean())
            else:
                avg_sim = 1.0

            cluster = AlertCluster(
                alert_ids    = [alerts[i].id for i in member_indices],
                source_types = source_types,
                max_severity = max_sev,
                avg_similarity = avg_sim,
                combined_text  = combined_text,
                alert_count    = len(member_indices),
            )

            # Back-assign cluster_id to alert objects
            for i in member_indices:
                alerts[i].cluster_id = cluster.cluster_id
                # update DB row
                from src.db import AlertRow
                session.query(AlertRow).filter(
                    AlertRow.id == alerts[i].id
                ).update({"cluster_id": cluster.cluster_id})

            upsert_cluster(session, cluster)
            clusters.append(cluster)

    cross_source = sum(1 for c in clusters if len(c.source_types) > 1)
    print(f"[correlate] Cross-source clusters: {cross_source}/{len(clusters)}")
    return clusters


# ── LangGraph node ────────────────────────────────────────────────────────────

def correlate_node(state: dict) -> dict:
    from src.schema import NormalizedAlert
    alerts_raw = state.get("alerts", [])
    alerts = [NormalizedAlert(**a) for a in alerts_raw]
    clusters = correlate_alerts(alerts)
    return {
        **state,
        "alerts":   [a.model_dump(exclude={"embedding"}) for a in alerts],
        "clusters": [c.model_dump() for c in clusters],
        "stage":    "classify",
    }
