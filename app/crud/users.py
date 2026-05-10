"""
Cyber Atlas - User CRUD Operations

Database operations for User management.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.apikey import APIKey
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import verify_password, get_password_hash, generate_api_key, hash_api_key
from app.core.logging import logger, log_security_event
from app.core.config import settings


# Account lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


async def get_user(db: AsyncSession, user_id: int) -> Optional[User]:
    """
    Get a user by ID.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        User if found, None otherwise
    """
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """
    Get a user by email address.
    
    Args:
        db: Database session
        email: Email address
    
    Returns:
        User if found, None otherwise
    """
    result = await db.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )
    return result.scalar_one_or_none()


async def get_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100,
    include_inactive: bool = False,
) -> Tuple[List[User], int]:
    """
    Get a list of users with pagination.
    
    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum number of records to return
        include_inactive: Whether to include inactive users
    
    Returns:
        Tuple of (user list, total count)
    """
    query = select(User)
    count_query = select(func.count(User.id))
    
    if not include_inactive:
        query = query.where(User.is_active == True)
        count_query = count_query.where(User.is_active == True)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()
    
    # Get users
    result = await db.execute(
        query
        .order_by(desc(User.created_at))
        .offset(skip)
        .limit(limit)
    )
    users = list(result.scalars().all())
    
    return users, total


async def create_user(
    db: AsyncSession,
    user_data: UserCreate,
) -> User:
    """
    Create a new user.
    
    Args:
        db: Database session
        user_data: User creation data
    
    Returns:
        Created user
    
    Raises:
        ValueError: If email already exists
    """
    # Check if email exists
    existing = await get_user_by_email(db, user_data.email)
    if existing:
        raise ValueError(f"Email {user_data.email} is already registered")
    
    # Hash password
    hashed_password = get_password_hash(user_data.password)
    
    user = User(
        email=user_data.email.lower(),
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        is_admin=user_data.is_admin,
        is_active=True,
    )
    
    db.add(user)
    await db.flush()
    await db.refresh(user)
    
    logger.info(f"Created user: {user.email}")
    log_security_event(
        "user_created",
        f"New user created: {user.email}",
        user_email=user.email,
    )
    
    return user


async def update_user(
    db: AsyncSession,
    user_id: int,
    user_data: UserUpdate,
) -> Optional[User]:
    """
    Update an existing user.
    
    Args:
        db: Database session
        user_id: User ID
        user_data: Updated user data
    
    Returns:
        Updated user if found, None otherwise
    """
    user = await get_user(db, user_id)
    if not user:
        return None
    
    update_data = user_data.model_dump(exclude_unset=True)
    
    # Check if email is being changed and is unique
    if "email" in update_data:
        update_data["email"] = update_data["email"].lower()
        existing = await get_user_by_email(db, update_data["email"])
        if existing and existing.id != user_id:
            raise ValueError(f"Email {update_data['email']} is already registered")
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    await db.flush()
    await db.refresh(user)
    
    logger.info(f"Updated user {user_id}: {user.email}")
    return user


async def update_user_password(
    db: AsyncSession,
    user_id: int,
    new_password: str,
) -> bool:
    """
    Update a user's password.
    
    Args:
        db: Database session
        user_id: User ID
        new_password: New password (plain text)
    
    Returns:
        True if updated, False if user not found
    """
    user = await get_user(db, user_id)
    if not user:
        return False
    
    user.hashed_password = get_password_hash(new_password)
    await db.flush()
    
    logger.info(f"Password updated for user {user_id}")
    log_security_event(
        "password_changed",
        "User password was changed",
        user_email=user.email,
    )
    
    return True


async def delete_user(db: AsyncSession, user_id: int) -> bool:
    """
    Delete a user (soft delete - deactivate).
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        True if deleted, False if not found
    """
    user = await get_user(db, user_id)
    if not user:
        return False
    
    user.is_active = False
    await db.flush()
    
    logger.info(f"Deactivated user {user_id}: {user.email}")
    log_security_event(
        "user_deactivated",
        f"User deactivated: {user.email}",
        user_email=user.email,
    )
    
    return True


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
    client_ip: Optional[str] = None,
) -> Tuple[Optional[User], str]:
    """
    Authenticate a user with email and password.
    
    Args:
        db: Database session
        email: User email
        password: User password
        client_ip: Client IP address for logging
    
    Returns:
        Tuple of (User if authenticated, error message if not)
    """
    user = await get_user_by_email(db, email)
    
    if not user:
        log_security_event(
            "failed_login",
            f"Login attempt for non-existent user: {email}",
            client_ip=client_ip,
        )
        return None, "Invalid email or password"
    
    # Check if account is locked
    can_login, reason = user.can_login()
    if not can_login:
        log_security_event(
            "blocked_login",
            f"Login blocked for {email}: {reason}",
            client_ip=client_ip,
            user_email=email,
        )
        return None, reason
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        # Increment failed attempts
        user.failed_login_attempts += 1
        
        # Lock account if too many failures
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=LOCKOUT_DURATION_MINUTES
            )
            log_security_event(
                "account_locked",
                f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts",
                client_ip=client_ip,
                user_email=email,
            )
        else:
            log_security_event(
                "failed_login",
                f"Invalid password (attempt {user.failed_login_attempts}/{MAX_FAILED_ATTEMPTS})",
                client_ip=client_ip,
                user_email=email,
            )
        
        await db.flush()
        return None, "Invalid email or password"
    
    # Successful login - reset counters
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    await db.flush()
    
    log_security_event(
        "successful_login",
        f"User logged in successfully",
        client_ip=client_ip,
        user_email=email,
    )
    
    return user, ""


async def create_default_admin(db: AsyncSession) -> Optional[User]:
    """
    Create the default admin user if it doesn't exist.
    
    Args:
        db: Database session
    
    Returns:
        Created admin user, or None if already exists
    """
    # Check if admin exists
    existing = await get_user_by_email(db, settings.default_admin_email)
    if existing:
        logger.info(f"Default admin already exists: {settings.default_admin_email}")
        return None
    
    # Create admin user
    admin_data = UserCreate(
        email=settings.default_admin_email,
        password=settings.default_admin_password,
        full_name="Admin User",
        is_admin=True,
    )
    
    admin = await create_user(db, admin_data)
    logger.info(f"Created default admin user: {admin.email}")
    
    return admin


# ============================================================================
# API Key Operations
# ============================================================================

async def create_api_key(
    db: AsyncSession,
    user_id: int,
    name: str,
    expires_in_days: Optional[int] = None,
    scopes: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> Tuple[APIKey, str]:
    """
    Create a new API key for a user.
    
    Args:
        db: Database session
        user_id: User ID
        name: API key name
        expires_in_days: Days until expiration
        scopes: List of allowed scopes
        rate_limit: Custom rate limit
    
    Returns:
        Tuple of (APIKey object, raw API key string)
    """
    # Generate API key
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:12]
    
    # Calculate expiration
    expires_at = None
    if expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    
    # Convert scopes to string
    scopes_str = None
    if scopes:
        scopes_str = ",".join(scopes)
    
    api_key = APIKey(
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=user_id,
        expires_at=expires_at,
        scopes=scopes_str,
        rate_limit=rate_limit,
    )
    
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)
    
    logger.info(f"Created API key '{name}' for user {user_id}")
    
    return api_key, raw_key


async def get_api_key_by_hash(db: AsyncSession, key_hash: str) -> Optional[APIKey]:
    """
    Get an API key by its hash.
    
    Args:
        db: Database session
        key_hash: SHA256 hash of the API key
    
    Returns:
        APIKey if found, None otherwise
    """
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash)
    )
    return result.scalar_one_or_none()


async def validate_api_key(
    db: AsyncSession,
    raw_key: str,
) -> Tuple[Optional[APIKey], Optional[User], str]:
    """
    Validate an API key and return the associated user.
    
    Args:
        db: Database session
        raw_key: Raw API key string
    
    Returns:
        Tuple of (APIKey, User, error message)
    """
    key_hash = hash_api_key(raw_key)
    api_key = await get_api_key_by_hash(db, key_hash)
    
    if not api_key:
        return None, None, "Invalid API key"
    
    if not api_key.is_valid():
        if api_key.is_expired():
            return None, None, "API key has expired"
        return None, None, "API key is inactive"
    
    # Get user
    user = await get_user(db, api_key.user_id)
    if not user or not user.is_active:
        return None, None, "User not found or inactive"
    
    # Update usage tracking
    api_key.last_used = datetime.now(timezone.utc)
    api_key.usage_count += 1
    await db.flush()
    
    return api_key, user, ""


async def get_user_api_keys(
    db: AsyncSession,
    user_id: int,
) -> List[APIKey]:
    """
    Get all API keys for a user.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        List of API keys
    """
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == user_id)
        .order_by(desc(APIKey.created_at))
    )
    return list(result.scalars().all())


async def revoke_api_key(
    db: AsyncSession,
    api_key_id: int,
    user_id: int,
) -> bool:
    """
    Revoke (deactivate) an API key.
    
    Args:
        db: Database session
        api_key_id: API key ID
        user_id: User ID (for authorization)
    
    Returns:
        True if revoked, False otherwise
    """
    result = await db.execute(
        select(APIKey).where(
            and_(
                APIKey.id == api_key_id,
                APIKey.user_id == user_id,
            )
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        return False
    
    api_key.is_active = False
    await db.flush()
    
    logger.info(f"Revoked API key {api_key_id}")
    
    return True
