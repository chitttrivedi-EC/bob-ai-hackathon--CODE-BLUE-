"""
graph.py — LangGraph StateGraph definition for ThreatLens AI pipeline.

Pipeline stages:
  ingest → correlate → classify → map_attack → bluf → END

Each node is a function that receives the shared state dict and returns
an updated state dict. The state flows unchanged through edges.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from langgraph.graph import StateGraph, END, START
from langgraph.graph.state import CompiledStateGraph
from typing import TypedDict, List, Any, cast


# ── State schema for LangGraph ────────────────────────────────────────────────

class PipelineStateDict(TypedDict, total=False):
    input_file: str
    raw_alerts: List[Any]
    alerts:     List[Any]
    clusters:   List[Any]
    briefs:     List[Any]
    errors:     List[str]
    stage:      str


# ── Node wrappers (import lazily to avoid slow load) ─────────────────────────

def ingest_node(state: PipelineStateDict) -> PipelineStateDict:
    from src.pipeline.ingest import ingest_node as _node
    print("\n" + "="*60)
    print("  STAGE 1 / 5 — INGEST & NORMALISE")
    print("="*60)
    return cast(PipelineStateDict, _node(cast(dict, state)))


def correlate_node(state: PipelineStateDict) -> PipelineStateDict:
    from src.pipeline.correlate import correlate_node as _node
    print("\n" + "="*60)
    print("  STAGE 2 / 5 — SEMANTIC CORRELATION (FAISS)")
    print("="*60)
    return cast(PipelineStateDict, _node(cast(dict, state)))


def classify_node(state: PipelineStateDict) -> PipelineStateDict:
    from src.pipeline.classify import classify_node as _node
    print("\n" + "="*60)
    print("  STAGE 3 / 5 — THREAT CLASSIFICATION (RandomForest)")
    print("="*60)
    return cast(PipelineStateDict, _node(cast(dict, state)))


def map_attack_node(state: PipelineStateDict) -> PipelineStateDict:
    from src.pipeline.map_attack import map_attack_node as _node
    print("\n" + "="*60)
    print("  STAGE 4 / 5 — MITRE ATT&CK MAPPING")
    print("="*60)
    return cast(PipelineStateDict, _node(cast(dict, state)))


def bluf_node(state: PipelineStateDict) -> PipelineStateDict:
    from src.pipeline.bluf import bluf_node as _node
    print("\n" + "="*60)
    print("  STAGE 5 / 5 — BLUF GENERATION (IBM watsonx Granite-3)")
    print("="*60)
    return cast(PipelineStateDict, _node(cast(dict, state)))


# ── Graph construction ────────────────────────────────────────────────────────

def build_pipeline() -> CompiledStateGraph:
    graph = StateGraph(cast(Any, PipelineStateDict))

    graph.add_node("ingest",      ingest_node)
    graph.add_node("correlate",   correlate_node)
    graph.add_node("classify",    classify_node)
    graph.add_node("map_attack",  map_attack_node)
    graph.add_node("bluf",        bluf_node)

    graph.add_edge(START,        "ingest")

    graph.add_edge("ingest",     "correlate")
    graph.add_edge("correlate",  "classify")
    graph.add_edge("classify",   "map_attack")
    graph.add_edge("map_attack", "bluf")
    graph.add_edge("bluf",       END)

    return graph.compile()


# ── Quick test if run directly ────────────────────────────────────────────────
if __name__ == "__main__":
    pipeline = build_pipeline()
    print("LangGraph pipeline compiled successfully.")
    print("Nodes:", list(pipeline.get_graph().nodes.keys()))
