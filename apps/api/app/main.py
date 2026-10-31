"""
FastAPI Main Application for SOC Analisis Engine.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[3]))

from apps.api.app.core.config import settings
from apps.api.app.api.v1 import api_v1_router


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="Intelligent Priority Awareness & Analysis Platform for SOC Alert Triage (Guo et al. 2026)",
    )

    # Enable CORS for React Vite Frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API v1 routes
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    # Mount compiled frontend static assets if available
    web_dist = Path(__file__).resolve().parents[3] / "apps" / "web" / "dist"
    if web_dist.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(web_dist), html=True), name="web_dist")

    @app.get("/health", tags=["Health"])
    def health_check():
        return {
            "status": "HEALTHY",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": settings.VERSION,
            "engine": "AHP-FFT-PCC-2026",
        }

    @app.get("/", tags=["Root"])
    def root():
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs_url": "/docs",
            "api_prefix": settings.API_V1_PREFIX,
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apps.api.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
