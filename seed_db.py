
import asyncio
import random
from datetime import datetime, timedelta
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal
from app.crud.iocs import create_ioc
from app.schemas.ioc import IOCCreate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock Data Pools
THREAT_ACTORS = ["APT28", "Lazarus", "APT29", "Wizard Spider", "Sandworm", "OilRig", "Equation Group"]
MALWARE_FAMILIES = ["Cobalt Strike", "Mimikatz", "Emotet", "TrickBot", "QakBot", "PlugX", "FormBook"]
COUNTRIES = ["US", "CN", "RU", "DE", "FR", "IN", "JP", "BR", "IR", "KP"]
IOC_TYPES = ["ip", "domain", "hash", "url"]
SOURCES = ["AlienVault", "RiskIQ", "CrowdStrike", "Mandiant", "Internal"]

async def seed_data():
    async with AsyncSessionLocal() as session:
        logger.info("Starting database seeding...")
        
        # Create 200 Mock IOCs
        for i in range(200):
            ioc_type = random.choice(IOC_TYPES)
            
            # Generate random value based on type
            if ioc_type == "ip":
                value = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            elif ioc_type == "domain":
                value = f"malicious-{random.randint(1000,9999)}.com"
            elif ioc_type == "hash":
                value = f"a{random.randint(1000000,9999999)}bc{random.randint(1000,9999)}"
            elif ioc_type == "url":
                value = f"http://bad-site-{random.randint(100,999)}.org/login"

            # Random Dates within last 30 days or today (for "Active" stats)
            created_at = datetime.now() - timedelta(days=random.randint(0, 30))
            is_recent = random.random() > 0.7  # 30% chance to be "today"

            ioc_data = IOCCreate(
                type=ioc_type,
                value=value,
                source=random.choice(SOURCES),
                risk=random.randint(5, 10), # High risk for visual impact
                country=random.choice(COUNTRIES),
                malware_family=random.choice(MALWARE_FAMILIES),
                confidence=random.randint(60, 100),
                tags=[random.choice(THREAT_ACTORS)]
            )

            try:
                await create_ioc(session, ioc_data)
            except Exception as e:
                # Ignore dupes
                pass
        
        await session.commit()
        logger.info("Database seeding completed! Dashboard should now have data.")




async def seed_full():
    """Seed IOCs and MITRE data."""
    try:
        from app.services.mitre import run_mitre_sync
        await seed_data()
        print("\n\n=== Starting MITRE ATT&CK Ingestion (This may take 1-2 minutes) ===")
        await run_mitre_sync()
        print("=== MITRE Ingestion Completed ===")
    except Exception as e:
        print(f"Error during full seed: {e}")

if __name__ == "__main__":
    import sys
    import os
    
    # Add project root to path
    sys.path.append(os.getcwd())
    
    if len(sys.argv) > 1 and sys.argv[1] == "full":
        asyncio.run(seed_full())
    else:
        asyncio.run(seed_data())
