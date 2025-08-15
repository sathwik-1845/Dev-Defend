from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..models.project import Project
from ..models.scan_result import ScanResult

async def get_or_create_project(session: AsyncSession, name: str, description: str | None = None) -> Project:
    res = await session.execute(select(Project).where(Project.name == name))
    proj = res.scalar_one_or_none()
    if proj:
        return proj
    proj = Project(name=name, description=description)
    session.add(proj)
    await session.commit()
    await session.refresh(proj)
    return proj

async def save_findings(session: AsyncSession, project_id: str, file_name: str, language: str, entries: list[dict]) -> list[ScanResult]:
    out: list[ScanResult] = []
    for e in entries:
        rec = ScanResult(
            project_id=project_id,
            file_name=file_name,
            language=language,
            vulnerability_type=e["vulnerability_type"],
            severity=e["severity"],
            original_snippet=e["original_snippet"],
            suggested_fix=e.get("suggested_fix"),
            explanation=e.get("explanation"),
        )
        session.add(rec)
        out.append(rec)
    await session.commit()
    for r in out:
        await session.refresh(r)
    return out

async def get_project_stats(session: AsyncSession, project_id: str):
    q = (
        select(
            ScanResult.vulnerability_type,
            func.count(ScanResult.id),
            func.sum(func.case((ScanResult.severity >= 3, 1), else_=0)).label("high_crit")
        )
        .where(ScanResult.project_id == project_id)
        .group_by(ScanResult.vulnerability_type)
    )
    res = await session.execute(q)
    rows = res.all()
    total = sum(r[1] for r in rows)
    high_crit = sum(r[2] for r in rows)
    by_type = [{"vulnerability_type": r[0], "count": r[1]} for r in rows]
    return {"total": total, "high_crit": high_crit, "by_type": by_type}

async def list_scans(session: AsyncSession, project_id: str, limit: int = 100):
    q = (
        select(ScanResult)
        .where(ScanResult.project_id == project_id)
        .order_by(ScanResult.created_at.desc())
        .limit(limit)
    )
    res = await session.execute(q)
    return [row[0] for row in res.all()]