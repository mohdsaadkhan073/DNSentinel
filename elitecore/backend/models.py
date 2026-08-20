from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime

from database import Base


class DNSQuery(Base):
    """Persisted form of a SecurityDecision event (see schemas.py for the contract)."""

    __tablename__ = "dns_queries"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    domain = Column(String, index=True, nullable=False)
    client_ip = Column(String, nullable=False)
    query_type = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    decision = Column(String, index=True, nullable=False)  # ALLOW | SUSPICIOUS | BLOCK

    threat_intel_matched = Column(Boolean, default=False)
    threat_intel_confidence = Column(Float, default=0.0)
    threat_category = Column(String, default="none")

    dga_probability = Column(Float, default=0.0)
    dga_classification = Column(String, default="NORMAL")

    tunneling_rate = Column(Float, default=0.0)
    tunneling_detected = Column(Boolean, default=False)

    rationale = Column(String, default="")
