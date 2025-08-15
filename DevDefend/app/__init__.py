from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String
from uuid import uuid4
from ..db import Base

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), index=True, unique=True)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    scans = relationship("ScanResult", back_populates="project", cascade="all,delete")