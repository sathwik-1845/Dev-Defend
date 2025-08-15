from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import ide, ci_cd, analytics
from .db import init_db
from .websocket import router as ws_router

app = FastAPI(title="Vulnerability Scanner API", version="0.1.0")

# CORS (adjust for your IDE/plugin origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

app.include_router(ide.router, prefix="/ide", tags=["IDE"])
app.include_router(ci_cd.router, prefix="/ci-cd", tags=["CI/CD"])
app.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
app.include_router(ws_router, tags=["WebSocket"])

@app.on_event("startup")
async def on_startup():
    await init_db()

@app.get("/health")
async def health():
    return {"status": "ok"}
