from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_session
from ..services.classify import classify_code
from ..services.fix import suggest_fix
from ..services.store import get_or_create_project, save_findings

router = APIRouter()

class RepoFile(BaseModel):
    path: str
    language: str
    content: str

class RepoScanRequest(BaseModel):
    project_name: str = Field(..., examples=["org/repo"])
    files: List[RepoFile]
    fail_on_severity: int = 3  # 3=High, 4=Critical → fail pipeline

class RepoScanResult(BaseModel):
    file_path: str
    findings_count: int

class RepoScanResponse(BaseModel):
    project_id: str
    summary: List[RepoScanResult]
    total_findings: int
    failed: bool

@router.post("/scan", response_model=RepoScanResponse)
async def scan_repo(req: RepoScanRequest, session: AsyncSession = Depends(get_session)):
    if not req.files:
        raise HTTPException(400, "No files provided")

    project = await get_or_create_project(session, req.project_name)
    total = 0
    summary: List[RepoScanResult] = []
    pipeline_fail = False

    for f in req.files:
        findings = await classify_code(f.content, f.language)
        entries = []
        max_sev = 0
        for fd in findings:
            expl, fix = await suggest_fix(fd, f.language)
            entries.append({
                "vulnerability_type": fd.vulnerability_type,
                "severity": fd.severity,
                "original_snippet": fd.snippet,
                "suggested_fix": fix,
                "explanation": expl,
            })
            max_sev = max(max_sev, fd.severity)
        await save_findings(session, project.id, f.path, f.language, entries)
        total += len(entries)
        summary.append(RepoScanResult(file_path=f.path, findings_count=len(entries)))
        if max_sev >= req.fail_on_severity:
            pipeline_fail = True

    return RepoScanResponse(
        project_id=project.id,
        summary=summary,
        total_findings=total,
        failed=pipeline_fail
    )