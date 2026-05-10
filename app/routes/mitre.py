"""
Cyber Atlas - MITRE ATT&CK Routes

API endpoints for accessing MITRE ATT&CK data.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, desc, asc

from app.core.database import get_db
from app.models.mitre import (
    MitreTactic, MitreTechnique, MitreGroup, MitreSoftware, MitreMitigation, mitre_relationships
)
from app.services.mitre import run_mitre_sync
from app.routes.auth import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

# -----------------------------------------------------------------------------
# Data Access - Base
# -----------------------------------------------------------------------------

@router.get("/tactics")
async def get_tactics(
    db: AsyncSession = Depends(get_db),
    # current_user: User = Depends(get_current_active_user)
):
    """List all tactics."""
    result = await db.execute(select(MitreTactic).order_by(MitreTactic.name))
    return result.scalars().all()

@router.get("/techniques")
async def get_techniques(
    tactic: Optional[str] = None,
    search: Optional[str] = None,
    is_subtechnique: Optional[bool] = None,
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """
    List techniques with filtering.
    """
    query = select(MitreTechnique)
    
    if tactic:
        # Join not implemented in simple list, but can filter by tactics if needed
        # For now, simplest is filter by text match if we stored it, or use valid join
        query = query.join(MitreTechnique.tactics).where(or_(
            MitreTactic.short_name == tactic,
            MitreTactic.name == tactic
        ))
    
    if search:
        query = query.where(or_(
            MitreTechnique.name.ilike(f"%{search}%"),
            MitreTechnique.external_id.ilike(f"%{search}%"),
            MitreTechnique.description.ilike(f"%{search}%")
        ))
        
    if is_subtechnique is not None:
        query = query.where(MitreTechnique.is_subtechnique == is_subtechnique)
        
    query = query.limit(limit).offset((page - 1) * limit)
    
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/techniques/{external_id}")
async def get_technique_by_id(
    external_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get technique by ID (e.g. T1566)."""
    result = await db.execute(select(MitreTechnique).where(MitreTechnique.external_id == external_id))
    tech = result.scalar_one_or_none()
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")
    return tech

@router.get("/groups")
async def get_groups(
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List groups."""
    query = select(MitreGroup)
    if search:
        query = query.where(or_(
            MitreGroup.name.ilike(f"%{search}%"),
            MitreGroup.external_id.ilike(f"%{search}%")
        ))
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/software")
async def get_software(
    search: Optional[str] = None,
    is_malware: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """List software/malware."""
    query = select(MitreSoftware)
    if search:
        query = query.where(or_(
            MitreSoftware.name.ilike(f"%{search}%"),
            MitreSoftware.external_id.ilike(f"%{search}%")
        ))
    if is_malware is not None:
        query = query.where(MitreSoftware.is_malware == is_malware)
        
    result = await db.execute(query.limit(100))
    return result.scalars().all()

@router.get("/mitigations")
async def get_mitigations(
    db: AsyncSession = Depends(get_db),
):
    """List mitigations."""
    result = await db.execute(select(MitreMitigation).limit(100))
    return result.scalars().all()

# -----------------------------------------------------------------------------
# Operations
# -----------------------------------------------------------------------------

@router.post("/sync")
async def trigger_mitre_sync(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
):
    """
    Trigger MITRE ATT&CK synchronization.
    """
    # In a real app we'd verify admin status
    background_tasks.add_task(run_mitre_sync)
    return {"status": "accepted", "message": "MITRE sync started in background"}
