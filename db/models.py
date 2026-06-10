from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import relationship
from db.database import Base


class Settings(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(64), unique=True, nullable=False, index=True)
    value = Column(Text)
    description = Column(String(256))
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vit_number = Column(String(32), unique=True, nullable=False, index=True)
    cve_id = Column(String(32), index=True)
    hostname = Column(String(128), index=True)
    ip_address = Column(String(64))
    server_class = Column(String(64))
    severity = Column(String(32))
    severity_level = Column(Integer, default=2)  # 1=Critical, 2=High, 3=Medium, 4=Low
    state = Column(String(32), default="Open", index=True)
    short_description = Column(Text)
    assignment_group = Column(String(256))
    opened_at = Column(DateTime)
    updated_at = Column(DateTime)
    raw_description = Column(Text)
    raw_recommendation = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    last_import_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    analysis = relationship("VulnAnalysis", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan")
    history = relationship("VulnHistory", back_populates="vulnerability", cascade="all, delete-orphan")


class VulnAnalysis(Base):
    __tablename__ = "vuln_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), unique=True, nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(Text)
    attack_vector = Column(String(32))
    attack_complexity = Column(String(32))
    privileges_required = Column(String(32))
    user_interaction = Column(String(32))
    affected_products = Column(Text)
    remediation_steps = Column(Text)
    detection_logic = Column(Text)
    exploit_status = Column(String(64))
    ai_risk_summary = Column(Text)
    ai_fix_priority = Column(String(32))
    ai_remediation_guide = Column(Text)
    detected_components = Column(Text)  # JSON array of {name, version, path}
    analyzed_at = Column(DateTime)

    vulnerability = relationship("Vulnerability", back_populates="analysis")


class VulnHistory(Base):
    __tablename__ = "vuln_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    field_changed = Column(String(64))
    old_value = Column(Text)
    new_value = Column(Text)
    changed_at = Column(DateTime, server_default=func.now())

    vulnerability = relationship("Vulnerability", back_populates="history")


class UploadLog(Base):
    __tablename__ = "upload_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(256))
    total_rows = Column(Integer)
    new_count = Column(Integer)
    updated_count = Column(Integer)
    error_count = Column(Integer)
    uploaded_at = Column(DateTime, server_default=func.now())
