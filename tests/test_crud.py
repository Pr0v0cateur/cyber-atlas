import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_crud_ioc_lifecycle(client: AsyncClient, db_session):
    """
    Test complete lifecycle of an IOC: Create, Read, Update, Delete.
    """
    # Setup Admin
    from app.models.user import User
    from app.core.security import get_password_hash
    admin = User(email="admin@crud.com", hashed_password=get_password_hash("Admin123!"), is_active=True, is_admin=True)
    db_session.add(admin)
    await db_session.commit()
    
    login = await client.post("/api/auth/login", data={"username": "admin@crud.com", "password": "Admin123!"})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Create
    ioc_data = {
        "type": "domain",
        "value": "crud-test.com",
        "source": "Manual",
        "risk": 5
    }
    create_res = await client.post("/api/search/iocs", json=ioc_data, headers=headers)
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]
    
    # 2. Read
    get_res = await client.get(f"/api/search/iocs/{created_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["value"] == "crud-test.com"
    
    # 3. Update
    update_data = {"risk": 10, "notes": "Updated note"}
    put_res = await client.put(f"/api/search/iocs/{created_id}", json=update_data, headers=headers)
    assert put_res.status_code == 200
    assert put_res.json()["risk"] == 10
    assert put_res.json()["notes"] == "Updated note"
    
    # 4. Delete
    del_res = await client.delete(f"/api/search/iocs/{created_id}", headers=headers)
    assert del_res.status_code == 204
    
    # Verify deletion
    check_res = await client.get(f"/api/search/iocs/{created_id}", headers=headers)
    assert check_res.status_code == 404
