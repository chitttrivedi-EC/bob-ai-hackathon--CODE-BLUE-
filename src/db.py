"""
db.py — SQLAlchemy + SQLite persistence layer for ThreatLens AI.

Tables:
  alerts   — all NormalizedAlert records
  clusters — AlertCluster metadata
  briefs   — BLUFBrief records (JSON-serialised)

Usage:
  from src.db import init_db, get_session
  init_db()
  with get_session() as session:
      session.add(...)
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer,
    String, Text, create_engine, event
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "data/threatintel.db")


# ── Engine setup ──────────────────────────────────────────────────────────────

def _get_engine():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    engine = create_engine(
        f"sqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
    )
    # Enable WAL mode for concurrent reads during Streamlit use
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()
    return engine


_engine = None
_SessionLocal = None


def _ensure_engine():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = _get_engine()
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


# ── ORM models ───────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class AlertRow(Base):
    __tablename__ = "alerts"

    id                = Column(String, primary_key=True)
    source_type       = Column(String, nullable=False)
    severity          = Column(String, nullable=False)
    timestamp         = Column(DateTime, nullable=False)
    raw_text          = Column(Text, nullable=False)
    source_ip         = Column(String)
    dest_ip           = Column(String)
    event_type        = Column(String)
    actor             = Column(String)
    location          = Column(String)
    cve_ids           = Column(Text, default="[]")    # JSON list
    confidence        = Column(Float, default=1.0)
    is_false_positive = Column(Boolean)
    cluster_id        = Column(String)
    threat_score      = Column(Float)
    attack_techniques = Column(Text, default="[]")    # JSON list
    created_at        = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ClusterRow(Base):
    __tablename__ = "clusters"

    cluster_id        = Column(String, primary_key=True)
    alert_ids         = Column(Text, default="[]")    # JSON list
    source_types      = Column(Text, default="[]")    # JSON list
    max_severity      = Column(String)
    avg_similarity    = Column(Float, default=0.0)
    combined_text     = Column(Text, default="")
    alert_count       = Column(Integer, default=0)
    threat_score      = Column(Float)
    is_false_positive = Column(Boolean)
    attack_techniques = Column(Text, default="[]")    # JSON list of AttackTechnique dicts
    bluf_json         = Column(Text)                  # JSON BLUFBrief
    created_at        = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BriefRow(Base):
    __tablename__ = "briefs"

    cluster_id         = Column(String, primary_key=True)
    bottom_line        = Column(Text)
    confidence         = Column(String)
    supporting_detail  = Column(Text)
    techniques_summary = Column(Text)
    recommended_action = Column(Text)
    classification     = Column(String)
    generated_by       = Column(String)
    generated_at       = Column(DateTime)
    is_fallback        = Column(Boolean, default=False)


# ── Public API ────────────────────────────────────────────────────────────────

def init_db(reset: bool = False):
    """Create tables. If reset=True, drop all first."""
    _ensure_engine()
    assert _engine is not None
    if reset:
        Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    _ensure_engine()
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ── Convenience helpers ───────────────────────────────────────────────────────

def upsert_alert(session: Session, alert) -> None:
    """Insert or update a NormalizedAlert ORM row."""
    row = AlertRow(
        id=alert.id,
        source_type=alert.source_type.value,
        severity=alert.severity.value,
        timestamp=alert.timestamp,
        raw_text=alert.raw_text,
        source_ip=alert.source_ip,
        dest_ip=alert.dest_ip,
        event_type=alert.event_type,
        actor=alert.actor,
        location=alert.location,
        cve_ids=json.dumps(alert.cve_ids),
        confidence=alert.confidence,
        is_false_positive=alert.is_false_positive,
        cluster_id=alert.cluster_id,
        threat_score=alert.threat_score,
        attack_techniques=json.dumps(alert.attack_techniques),
    )
    session.merge(row)


def upsert_cluster(session: Session, cluster) -> None:
    """Insert or update an AlertCluster ORM row."""
    bluf_json = None
    if cluster.bluf:
        bluf_json = cluster.bluf.model_dump_json()

    attack_list = [t.model_dump() for t in cluster.attack_techniques]

    row = ClusterRow(
        cluster_id=cluster.cluster_id,
        alert_ids=json.dumps(cluster.alert_ids),
        source_types=json.dumps([s.value for s in cluster.source_types]),
        max_severity=cluster.max_severity.value,
        avg_similarity=cluster.avg_similarity,
        combined_text=cluster.combined_text,
        alert_count=cluster.alert_count,
        threat_score=cluster.threat_score,
        is_false_positive=cluster.is_false_positive,
        attack_techniques=json.dumps(attack_list),
        bluf_json=bluf_json,
    )
    session.merge(row)


def load_all_alerts(session: Session):
    """Return all AlertRow objects."""
    return session.query(AlertRow).all()


def load_all_clusters(session: Session):
    """Return all ClusterRow objects."""
    return session.query(ClusterRow).order_by(ClusterRow.threat_score.desc()).all()


def load_all_briefs(session: Session):
    """Return all BriefRow objects."""
    return session.query(BriefRow).all()
