from fastapi import APIRouter
from .alerts import router as alerts_router
from .cases import router as cases_router
from .analytics import router as analytics_router
from .graph import router as graph_router

api_v1_router = APIRouter()
api_v1_router.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
api_v1_router.include_router(cases_router, prefix="/cases", tags=["Cases"])
api_v1_router.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])
api_v1_router.include_router(graph_router, prefix="/graph", tags=["Knowledge Graph"])

__all__ = ["api_v1_router"]
