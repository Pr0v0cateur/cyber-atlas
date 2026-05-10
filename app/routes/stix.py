from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.stix_object import STIXObject
from app.services.connector_manager import STIXConnectorManager


router = APIRouter(prefix="/stix", tags=["stix"])


@router.post("/collect")
async def trigger_stix_collection(db: AsyncSession = Depends(get_db)):
    """Manually trigger STIX data collection (maximum data)."""
    _ = db
    manager = STIXConnectorManager()
    stats = await manager.collect_all()
    return {"status": "success", "stats": stats}


@router.get("/stats")
async def get_stix_stats(db: AsyncSession = Depends(get_db)):
    """Get STIX database statistics."""
    total_result = await db.execute(select(func.count(STIXObject.id)))
    total = total_result.scalar_one()

    indicator_result = await db.execute(
        select(func.count(STIXObject.id)).where(STIXObject.type == "indicator")
    )
    indicators = indicator_result.scalar_one()

    observable_result = await db.execute(
        select(func.count(STIXObject.id)).where(STIXObject.observable_type.isnot(None))
    )
    observables = observable_result.scalar_one()

    return {
        "total_objects": total,
        "indicators": indicators,
        "observables": observables,
    }
