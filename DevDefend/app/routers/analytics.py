from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..db import get_session
from ..models.project import Project
from ..models.scan_result import ScanResult
from ..services.store import get_project_stats

router = APIRouter()

class ProjectStats(BaseModel):
    total: int
    high_crit: int
    by_type: list[dict]

class ScanItem(BaseModel):
    id: str
    file_name: str
    vulnerability_type: str
    severity: int
    created_at: str

class ScansResponse(BaseModel):
    project_id: str
    project_name: str
    stats: ProjectStats
    scans: list[ScanItem]

@router.get("/projects", response_model=list[dict])
async def list_projects(session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(Project))
    return [{"id": p.id, "name": p.name, "description": p.description} for p in res.scalars().all()]

@router.get("/project/{project_id}", response_model=ScansResponse)
async def project_scans(project_id: str, session: AsyncSession = Depends(get_session)):
    proj = await session.get(Project, project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    stats = await get_project_stats(session, project_id)
    res = await session.execute(
        select(ScanResult).where(ScanResult.project_id == project_id).order_by(ScanResult.created_at.desc()).limit(200)
    )
    scans = res.scalars().all()
    return ScansResponse(
        project_id=proj.id,
        project_name=proj.name,
        stats=ProjectStats(**stats),
        scans=[ScanItem(
            id=s.id,
            file_name=s.file_name,
            vulnerability_type=s.vulnerability_type,
            severity=s.severity,
            created_at=s.created_at.isoformat()
        ) for s in scans]
    )