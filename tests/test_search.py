import pytest
from httpx import AsyncClient
from datetime import datetime

@pytest.mark.asyncio
async def test_search_iocs(client: AsyncClient, db_session):
    """
    Test searching for IOCs.
    """
    # Seed DB
    from app.models.ioc import IOC
    from app.models.user import User
    from app.core.security import get_password_hash
    
    # Create user for auth
    user = User(email="user@test.com", hashed_password=get_password_hash("Pass123!"), is_active=True)
    db_session.add(user)
    
    # Create IOCs
    ioc1 = IOC(type="ip", value="10.0.0.1", source="Test", first_seen=datetime.now(), last_seen=datetime.now(), risk=5)
    ioc2 = IOC(type="domain", value="evil.com", source="Test", first_seen=datetime.now(), last_seen=datetime.now(), risk=9)
    db_session.add(ioc1)
    db_session.add(ioc2)
    await db_session.commit()
    
    # Login
    login_res = await client.post("/api/auth/login", data={"username": "user@test.com", "password": "Pass123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Search all
    res = await client.get("/api/search/iocs", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    
    # Filter by type
    res = await client.get("/api/search/iocs?type=ip", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["items"][0]["value"] == "10.0.0.1"
    
    # Search text
    res = await client.get("/api/search/iocs?q=evil", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1
    assert res.json()["items"][0]["value"] == "evil.com"
