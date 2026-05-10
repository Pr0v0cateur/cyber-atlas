#!/usr/bin/env python3
"""
Cyber Atlas - Historical Data Collection Script

Collect historical threat intelligence data from all STIX connectors.
Usage: python scripts/collect_historical.py --start 2024-11-01 --end 2026-01-13

This script:
1. Collects historical IOCs from ThreatFox, URLhaus, and OTX
2. Stores all data in the database
3. Provides progress logging and statistics
"""

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# Configure loguru for script output
logger.add(
    "logs/historical_collection.log",
    rotation="50 MB",
    retention="7 days",
    level="INFO",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)


async def collect_historical_data(
    start_date: str,
    end_date: str,
    connectors: Optional[list] = None
) -> dict:
    """
    Collect all historical data from STIX connectors.
    
    Args:
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        connectors: Optional list of connector names to use (default: all)
    
    Returns:
        Dictionary with collection statistics
    """
    from app.services.connector_manager import STIXConnectorManager
    from app.crud.stix import save_stix_bundle
    from app.core.database import AsyncSessionLocal
    
    start = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
    end = datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)
    
    logger.info("=" * 60)
    logger.info(f"CYBER ATLAS - HISTORICAL DATA COLLECTION")
    logger.info(f"Period: {start_date} → {end_date}")
    logger.info("=" * 60)
    
    manager = STIXConnectorManager()
    
    total_stats = {
        "start_date": start_date,
        "end_date": end_date,
        "connectors_processed": 0,
        "connectors_success": 0,
        "connectors_failed": 0,
        "total_objects": 0,
        "total_indicators": 0,
        "total_observables": 0,
        "total_relationships": 0,
        "details": {}
    }
    
    # Determine which connectors to run
    connector_keys = connectors if connectors else list(manager.connectors.keys())
    logger.info(f"Connectors to process: {connector_keys}")
    
    for key in connector_keys:
        connector = manager.connectors.get(key)
        if not connector:
            logger.warning(f"Connector '{key}' not found, skipping")
            continue
            
        total_stats["connectors_processed"] += 1
        logger.info(f"\n{'─' * 40}")
        logger.info(f"Processing: {connector.name}")
        logger.info(f"Supports historical: {connector.supports_historical()}")
        
        try:
            if connector.supports_historical():
                logger.info(f"Collecting historical data from {start_date} to {end_date}...")
                bundle = await connector.collect_historical(start, end)
            else:
                logger.info(f"Running current collection (historical not supported)...")
                bundle = await connector.collect()
            
            # Save to database
            async with AsyncSessionLocal() as session:
                stats = await save_stix_bundle(
                    session,
                    bundle,
                    connector.id,
                    connector.name
                )
                await session.commit()
            
            # Update totals
            total_stats["total_objects"] += stats.get("objects", 0)
            total_stats["total_indicators"] += stats.get("indicators", 0)
            total_stats["total_observables"] += stats.get("observables", 0)
            total_stats["total_relationships"] += stats.get("relationships", 0)
            total_stats["connectors_success"] += 1
            total_stats["details"][connector.name] = stats
            
            logger.success(f"✓ {connector.name}: {stats}")
            
        except Exception as e:
            logger.error(f"✗ Failed to collect from {connector.name}: {e}")
            total_stats["connectors_failed"] += 1
            total_stats["details"][connector.name] = {"error": str(e)}
    
    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("COLLECTION COMPLETE - SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Connectors: {total_stats['connectors_success']}/{total_stats['connectors_processed']} successful")
    logger.info(f"Total STIX Objects: {total_stats['total_objects']:,}")
    logger.info(f"  - Indicators: {total_stats['total_indicators']:,}")
    logger.info(f"  - Observables: {total_stats['total_observables']:,}")
    logger.info(f"  - Relationships: {total_stats['total_relationships']:,}")
    logger.info("=" * 60)
    
    return total_stats


async def run_standard_collection() -> dict:
    """
    Run standard (non-historical) collection from all connectors.
    Useful for regular data refreshes.
    """
    from app.services.connector_manager import STIXConnectorManager
    
    logger.info("Running standard STIX collection...")
    manager = STIXConnectorManager()
    return await manager.collect_all()


def main():
    """Main entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Collect historical threat intelligence data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect all data from November 2024 to now
  python scripts/collect_historical.py --start 2024-11-01
  
  # Collect specific date range
  python scripts/collect_historical.py --start 2024-11-01 --end 2025-01-01
  
  # Collect only from specific connectors
  python scripts/collect_historical.py --start 2024-11-01 --connectors threatfox urlhaus
  
  # Run standard (current) collection
  python scripts/collect_historical.py --current
        """
    )
    
    parser.add_argument(
        '--start',
        default='2024-11-01',
        help='Start date in YYYY-MM-DD format (default: 2024-11-01)'
    )
    parser.add_argument(
        '--end',
        default=datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        help='End date in YYYY-MM-DD format (default: today)'
    )
    parser.add_argument(
        '--connectors',
        nargs='+',
        help='Specific connectors to run (default: all available)'
    )
    parser.add_argument(
        '--current',
        action='store_true',
        help='Run current collection instead of historical'
    )
    
    args = parser.parse_args()
    
    try:
        if args.current:
            result = asyncio.run(run_standard_collection())
        else:
            result = asyncio.run(collect_historical_data(
                args.start,
                args.end,
                args.connectors
            ))
        
        print("\n✅ Collection completed successfully!")
        print(f"   Total objects: {result.get('total_objects', 0):,}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Collection failed: {e}")
        logger.exception("Collection failed with exception")
        sys.exit(1)


if __name__ == "__main__":
    main()
