"""
Apex-SOC Backend - FastAPI Application Factory
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import ingest, dashboard
from core.correlation import CorrelationEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown logic."""
    # Initialize the correlation engine singleton on startup
    app.state.correlation_engine = CorrelationEngine()
    print("[APEX-SOC] Correlation engine initialized.")
    yield
    # Cleanup on shutdown
    print("[APEX-SOC] Shutting down correlation engine.")


def create_app() -> FastAPI:
    """Application factory - creates and configures the FastAPI instance."""
    app = FastAPI(
        title="Apex-SOC API",
        description="Enterprise-grade Security Operations Center backend",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # --- CORS ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tighten in production using env var
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Routers ---
    app.include_router(ingest.router, prefix="/api", tags=["Ingest"])
    app.include_router(dashboard.router, prefix="/api", tags=["Dashboard"])

    @app.get("/api/health", tags=["Health"])
    async def health_check():
        return {"status": "ok", "service": "Apex-SOC"}

    return app


app = create_app()
