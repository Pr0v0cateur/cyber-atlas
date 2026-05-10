"""
Cyber Atlas - IOC CRUD Operations

Database operations for Indicators of Compromise.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from sqlalchemy import select, func, and_, or_, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert

from app.models.ioc import IOC
from app.schemas.ioc import IOCCreate, IOCUpdate, IOCSearchParams
from app.core.logging import logger


async def get_ioc(db: AsyncSession, ioc_id: int) -> Optional[IOC]:
    """
    Get a single IOC by ID.
    
    Args:
        db: Database session
        ioc_id: IOC ID
    
    Returns:
        IOC if found, None otherwise
    """
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    return result.scalar_one_or_none()


async def get_iocs(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100,
    order_by: str = "last_seen",
    order_desc: bool = True,
) -> List[IOC]:
    """
    Get a list of IOCs with pagination.
    
    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum number of records to return
        order_by: Field to order by
        order_desc: Whether to order descending
    
    Returns:
        List of IOCs
    """
    # Build order clause
    order_column = getattr(IOC, order_by, IOC.last_seen)
    order_clause = desc(order_column) if order_desc else asc(order_column)
    
    result = await db.execute(
        select(IOC)
        .order_by(order_clause)
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def create_ioc(db: AsyncSession, ioc_data: IOCCreate) -> IOC:
    """
    Create a new IOC.
    
    Args:
        db: Database session
        ioc_data: IOC data
    
    Returns:
        Created IOC
    """
    # Convert tags list to comma-separated string
    tags_str = None
    if ioc_data.tags:
        tags_str = ",".join(ioc_data.tags)
    
    ioc = IOC(
        type=ioc_data.type,
        value=ioc_data.value,
        source=ioc_data.source,
        first_seen=ioc_data.first_seen or datetime.now(timezone.utc),
        last_seen=ioc_data.last_seen or datetime.now(timezone.utc),
        country=ioc_data.country,
        risk=ioc_data.risk,
        notes=ioc_data.notes,
        raw=ioc_data.raw if hasattr(ioc_data, 'raw') else None,
        tags=tags_str,
        malware_family=ioc_data.malware_family,
        confidence=ioc_data.confidence,
    )
    
    db.add(ioc)
    await db.flush()
    await db.refresh(ioc)
    
    logger.debug(f"Created IOC: {ioc.type}:{ioc.value} from {ioc.source}")
    return ioc


async def create_iocs_bulk(
    db: AsyncSession,
    iocs_data: List[IOCCreate],
    skip_duplicates: bool = True,
) -> Tuple[int, int, int]:
    """
    Create multiple IOCs in bulk.
    
    Args:
        db: Database session
        iocs_data: List of IOC data
        skip_duplicates: Whether to skip duplicates
    
    Returns:
        Tuple of (created_count, skipped_count, error_count)
    """
    created = 0
    skipped = 0
    errors = 0
    
    for ioc_data in iocs_data:
        try:
            # Check for duplicate
            exists = await check_ioc_exists(
                db,
                ioc_type=ioc_data.type,
                value=ioc_data.value,
                source=ioc_data.source,
            )
            
            if exists:
                if skip_duplicates:
                    # Update last_seen timestamp
                    await update_ioc_last_seen(db, exists.id)
                    skipped += 1
                    continue
                else:
                    errors += 1
                    continue
            
            await create_ioc(db, ioc_data)
            created += 1
            
        except Exception as e:
            logger.error(f"Error creating IOC {ioc_data.value}: {e}")
            errors += 1
    
    await db.commit()
    logger.info(f"Bulk IOC create: {created} created, {skipped} skipped, {errors} errors")
    return created, skipped, errors


async def update_ioc(
    db: AsyncSession,
    ioc_id: int,
    ioc_data: IOCUpdate,
) -> Optional[IOC]:
    """
    Update an existing IOC.
    
    Args:
        db: Database session
        ioc_id: IOC ID
        ioc_data: Updated IOC data
    
    Returns:
        Updated IOC if found, None otherwise
    """
    ioc = await get_ioc(db, ioc_id)
    if not ioc:
        return None
    
    update_data = ioc_data.model_dump(exclude_unset=True)
    
    # Convert tags list to comma-separated string
    if "tags" in update_data and update_data["tags"]:
        update_data["tags"] = ",".join(update_data["tags"])
    
    for field, value in update_data.items():
        setattr(ioc, field, value)
    
    await db.flush()
    await db.refresh(ioc)
    
    logger.debug(f"Updated IOC {ioc_id}")
    return ioc


async def update_ioc_last_seen(db: AsyncSession, ioc_id: int) -> None:
    """
    Update the last_seen timestamp of an IOC.
    
    Args:
        db: Database session
        ioc_id: IOC ID
    """
    ioc = await get_ioc(db, ioc_id)
    if ioc:
        ioc.last_seen = datetime.now(timezone.utc)
        await db.flush()


async def delete_ioc(db: AsyncSession, ioc_id: int) -> bool:
    """
    Delete an IOC.
    
    Args:
        db: Database session
        ioc_id: IOC ID
    
    Returns:
        True if deleted, False if not found
    """
    ioc = await get_ioc(db, ioc_id)
    if not ioc:
        return False
    
    await db.delete(ioc)
    await db.flush()
    
    logger.debug(f"Deleted IOC {ioc_id}")
    return True


async def check_ioc_exists(
    db: AsyncSession,
    ioc_type: str,
    value: str,
    source: Optional[str] = None,
) -> Optional[IOC]:
    """
    Check if an IOC already exists.
    
    Args:
        db: Database session
        ioc_type: IOC type
        value: IOC value
        source: Optional source filter
    
    Returns:
        Existing IOC if found, None otherwise
    """
    query = select(IOC).where(
        and_(
            IOC.type == ioc_type,
            IOC.value == value,
        )
    )
    
    if source:
        query = query.where(IOC.source == source)
    
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def search_iocs(
    db: AsyncSession,
    params: IOCSearchParams,
) -> Tuple[List[IOC], int]:
    """
    Search IOCs with filters and pagination.
    
    Args:
        db: Database session
        params: Search parameters
    
    Returns:
        Tuple of (IOC list, total count)
    """
    # Base query
    query = select(IOC)
    count_query = select(func.count(IOC.id))
    
    # Build filters
    filters = []
    
    if params.q:
        # Full-text search on value and notes
        search_term = f"%{params.q}%"
        filters.append(
            or_(
                IOC.value.ilike(search_term),
                IOC.notes.ilike(search_term),
                IOC.tags.ilike(search_term),
                IOC.malware_family.ilike(search_term),
            )
        )
    
    if params.type:
        filters.append(IOC.type == params.type)
    
    if params.source:
        filters.append(IOC.source == params.source)
    
    if params.country:
        filters.append(IOC.country == params.country)
    
    if params.risk_min is not None:
        filters.append(IOC.risk >= params.risk_min)
    
    if params.risk_max is not None:
        filters.append(IOC.risk <= params.risk_max)
    
    if params.malware_family:
        filters.append(IOC.malware_family.ilike(f"%{params.malware_family}%"))
    
    if params.first_seen_after:
        filters.append(IOC.first_seen >= params.first_seen_after)
    
    if params.first_seen_before:
        filters.append(IOC.first_seen <= params.first_seen_before)
    
    if params.last_seen_after:
        filters.append(IOC.last_seen >= params.last_seen_after)
    
    if params.last_seen_before:
        filters.append(IOC.last_seen <= params.last_seen_before)
    
    # Apply filters
    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()
    
    # Apply ordering
    order_column = getattr(IOC, params.sort_by, IOC.last_seen)
    order_clause = desc(order_column) if params.sort_order == "desc" else asc(order_column)
    query = query.order_by(order_clause)
    
    # Apply pagination
    offset = (params.page - 1) * params.page_size
    query = query.offset(offset).limit(params.page_size)
    
    # Execute query
    result = await db.execute(query)
    iocs = list(result.scalars().all())
    
    return iocs, total


async def get_ioc_stats(db: AsyncSession) -> dict:
    """
    Get IOC statistics.
    
    Args:
        db: Database session
    
    Returns:
        Dictionary of statistics
    """
    # Total count
    total_result = await db.execute(select(func.count(IOC.id)))
    total_count = total_result.scalar_one()
    
    # Count by type
    type_result = await db.execute(
        select(IOC.type, func.count(IOC.id))
        .group_by(IOC.type)
    )
    by_type = dict(type_result.all())
    
    # Count by source
    source_result = await db.execute(
        select(IOC.source, func.count(IOC.id))
        .group_by(IOC.source)
    )
    by_source = dict(source_result.all())
    
    # Count by country (top 20)
    country_result = await db.execute(
        select(IOC.country, func.count(IOC.id))
        .where(IOC.country.isnot(None))
        .group_by(IOC.country)
        .order_by(desc(func.count(IOC.id)))
        .limit(20)
    )
    by_country = dict(country_result.all())
    
    # Count by risk
    risk_result = await db.execute(
        select(IOC.risk, func.count(IOC.id))
        .where(IOC.risk.isnot(None))
        .group_by(IOC.risk)
        .order_by(IOC.risk)
    )
    by_risk = {int(k): v for k, v in risk_result.all() if k is not None}
    
    return {
        "total_count": total_count,
        "by_type": by_type,
        "by_source": by_source,
        "by_country": by_country,
        "by_risk": by_risk,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


async def get_iocs_by_source(db: AsyncSession) -> dict:
    """
    Get IOC counts grouped by source.
    
    Args:
        db: Database session
    
    Returns:
        Dictionary of source -> count
    """
    result = await db.execute(
        select(IOC.source, func.count(IOC.id))
        .group_by(IOC.source)
        .order_by(desc(func.count(IOC.id)))
    )
    return dict(result.all())


async def get_iocs_by_country(db: AsyncSession, limit: int = 50) -> dict:
    """
    Get IOC counts grouped by country.
    
    Args:
        db: Database session
        limit: Maximum number of countries to return
    
    Returns:
        Dictionary of country -> count
    """
    result = await db.execute(
        select(IOC.country, func.count(IOC.id))
        .where(IOC.country.isnot(None))
        .group_by(IOC.country)
        .order_by(desc(func.count(IOC.id)))
        .limit(limit)
    )
    return dict(result.all())


async def get_ioc_timeline(
    db: AsyncSession,
    days: int = 30,
    group_by_type: bool = False,
) -> List[dict]:
    """
    Get IOC counts over time.
    
    Args:
        db: Database session
        days: Number of days to include
        group_by_type: Whether to group by IOC type
    
    Returns:
        List of timeline data points
    """
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    if group_by_type:
        result = await db.execute(
            select(
                func.date(IOC.first_seen).label("date"),
                IOC.type,
                func.count(IOC.id).label("count")
            )
            .where(IOC.first_seen >= start_date)
            .group_by(func.date(IOC.first_seen), IOC.type)
            .order_by(func.date(IOC.first_seen))
        )
        
        # Group by date
        timeline = {}
        for row in result.all():
            date_str = str(row.date)
            if date_str not in timeline:
                timeline[date_str] = {"date": date_str, "count": 0, "by_type": {}}
            timeline[date_str]["count"] += row.count
            timeline[date_str]["by_type"][row.type] = row.count
        
        return list(timeline.values())
    else:
        result = await db.execute(
            select(
                func.date(IOC.first_seen).label("date"),
                func.count(IOC.id).label("count")
            )
            .where(IOC.first_seen >= start_date)
            .group_by(func.date(IOC.first_seen))
            .order_by(func.date(IOC.first_seen))
        )
        
        return [{"date": str(row.date), "count": row.count} for row in result.all()]


    return dict(result.all())


async def get_top_malware_families(db: AsyncSession, limit: int = 5) -> dict:
    """
    Get top malware families.
    
    Args:
        db: Database session
        limit: Limit results
    
    Returns:
        Dictionary of family -> count
    """
    result = await db.execute(
        select(IOC.malware_family, func.count(IOC.id))
        .where(IOC.malware_family.isnot(None))
        .where(IOC.malware_family != "")
        .group_by(IOC.malware_family)
        .order_by(desc(func.count(IOC.id)))
        .limit(limit)
    )
    return dict(result.all())


async def cleanup_old_iocs(
    db: AsyncSession,
    days_old: int = 90,
    dry_run: bool = True,
) -> int:
    """
    Delete IOCs older than specified days.
    
    Args:
        db: Database session
        days_old: Delete IOCs last seen more than this many days ago
        dry_run: If True, only count without deleting
    
    Returns:
        Number of IOCs deleted (or would be deleted if dry_run)
    """
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
    
    # Count IOCs to delete
    count_result = await db.execute(
        select(func.count(IOC.id))
        .where(IOC.last_seen < cutoff_date)
    )
    count = count_result.scalar_one()
    
    if not dry_run and count > 0:
        from sqlalchemy import delete
        await db.execute(
            delete(IOC).where(IOC.last_seen < cutoff_date)
        )
        await db.commit()
        logger.info(f"Cleaned up {count} old IOCs (older than {days_old} days)")
    
    return count
