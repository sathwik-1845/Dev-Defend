from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List
from ..db import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from ..services.classify import classify_code
from ..services.fix import suggest_fix
from ..services.store import get_or_create_project, save_findings
from ..config import settings

router = APIRouter()

class CodeScanRequest(BaseModel):
    project_name: str = Field(..., examples=["my-repo"])
    language: str = Field(..., examples=["python"])
    file_name: str = Field(..., examples=["app/main.py"])
    code: str

class FindingResponse(BaseModel):
    id: str
    vulnerability_type: str
    severity: int
    original_snippet: str
    suggested_fix: str | None
    explanation: str | None
    file_name: str
    language: str

class CodeScanResponse(BaseModel):
    project_id: str
    file_name: str
    language: str
    findings: List[FindingResponse]

@router.post("/scan", response_model=CodeScanResponse)
async def scan_code(req: CodeScanRequest, session: AsyncSession = Depends(get_session)):
    if req.language.lower() not in settings.ALLOWED_LANGS:
        raise HTTPException(400, f"Unsupported language: {req.language}")

    # Guard file size
    if len(req.code.encode("utf-8")) > settings.MAX_FILE_SIZE_BYTES:
        raise HTTPException(413, "File too large")

    project = await get_or_create_project(session, name=req.project_name)
    findings = await classify_code(req.code, req.language)

    entries = []
    for f in findings:
        explanation = suggested_fix = None
        if settings.ENABLE_FIXES:
            explanation, suggested_fix = await suggest_fix(f, req.language)

        entries.append({
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "original_snippet": f.snippet,
            "suggested_fix": suggested_fix,
            "explanation": explanation,
        })

    saved = await save_findings(session, project.id, req.file_name, req.language, entries)

    return CodeScanResponse(
        project_id=project.id,
        file_name=req.file_name,
        language=req.language,
        findings=[
            FindingResponse(
                id=s.id,
                vulnerability_type=s.vulnerability_type,
                severity=s.severity,
                original_snippet=s.original_snippet,
                suggested_fix=s.suggested_fix,
                explanation=s.explanation,
                file_name=s.file_name,
                language=s.language,
            ) for s in saved
        ],
    )