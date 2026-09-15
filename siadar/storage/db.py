"""
Persistência: grava cada flow classificado em CSV e em banco SQL, em paralelo.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

DATA_DIR = Path(__file__).parent.parent.parent / "data"
CSV_PATH = DATA_DIR / "flows.csv"

# Nunca commitar uma URL de banco real — usar .env (gitignored). Ver .env.example.
DATABASE_URL = os.environ.get("SIADAR_DATABASE_URL", f"sqlite:///{DATA_DIR / 'siadar.db'}")

_engine = create_engine(DATABASE_URL)
_Session = sessionmaker(bind=_engine)


class FlowRecord(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    src_ip = Column(String, nullable=False)
    dst_ip = Column(String, nullable=False)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    label = Column(String)
    anomalous = Column(Integer)  # 0/1


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(_engine)


def save_flow(flow, label: str, anomalous: bool) -> None:
    """Grava o flow classificado em CSV e no banco SQL, em paralelo."""
    init_db()

    # CSV
    is_new = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(
                ["timestamp", "src_ip", "dst_ip", "packet_count", "byte_count", "label", "anomalous"]
            )
        writer.writerow(
            [
                datetime.now(timezone.utc).isoformat(),
                flow.src_ip,
                flow.dst_ip,
                flow.packet_count,
                flow.byte_count,
                label,
                int(anomalous),
            ]
        )

    # SQL
    session = _Session()
    try:
        session.add(
            FlowRecord(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                label=label,
                anomalous=int(anomalous),
            )
        )
        session.commit()
    finally:
        session.close()
