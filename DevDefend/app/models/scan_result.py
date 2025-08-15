from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Integer, ForeignKey, DateTime
from datetime import datetime
from uuid import uuid4
from ..db import Base

class ScanResult(Base):
    __tablename__ = "scan_results"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    file_name: Mapped[str] = mapped_column(String(512))
    language: Mapped[str] = mapped_column(String(32))
    vulnerability_type: Mapped[str] = mapped_column(String(128))
    severity: Mapped[int] = mapped_column(Integer)  # 1=Low, 2=Med, 3=High, 4=Critical
    original_snippet: Mapped[str] = mapped_column(Text)
    suggested_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="scans")