"""
Cyber Atlas - Authentication Routes

JWT authentication endpoints for login, logout, and user management.
"""

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from app.core.config import settings
from app.core.logging import logger, log_security_event
from app.crud import users as user_crud
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    Token,
    RefreshTokenRequest,
    LogoutResponse,
    CurrentUserResponse,
    UserInfo,
)
from app.schemas.user import (
    UserCreate,
    UserResponse,
    UserPasswordUpdate,
    UserAPIKeyCreate,
    UserAPIKeyCreatedResponse,
    UserAPIKeyResponse,
)
from app.models.user import User
from app.middleware.ratelimit import rate_limiter, auth_rate_limit, get_client_ip


router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency to get the current authenticated user.
    
    Args:
        request: FastAPI request
        token: JWT token from Authorization header
        db: Database session
    
    Returns:
        Authenticated user
    
    Raises:
        HTTPException: If authentication fails
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check for API key first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        api_key_obj, user, error = await user_crud.validate_api_key(db, api_key)
        if error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error,
            )
        request.state.api_key = api_key_obj
        return user
    
    # Check for JWT token
    if not token:
        raise credentials_exception
    
    payload = decode_access_token(token)
    if not payload:
        raise credentials_exception
    
    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception
    
    try:
        user = await user_crud.get_user(db, int(user_id))
    except ValueError:
        raise credentials_exception
    
    if not user or not user.is_active:
        raise credentials_exception
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency to get the current active user.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        Active user
    
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return current_user


async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Dependency to get the current admin user.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        Admin user
    
    Raises:
        HTTPException: If user is not admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


from fastapi import Response

@router.post("/login", response_model=LoginResponse)
@rate_limiter.limit(auth_rate_limit)
async def login(
    request: Request,
    response: Response,  # Required by slowapi
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return JWT tokens.
    
    - **username**: User email address
    - **password**: User password
    
    Returns access token, refresh token, and user info.
    """
    client_ip = get_client_ip(request)
    
    user, error = await user_crud.authenticate_user(
        db,
        email=form_data.username,
        password=form_data.password,
        client_ip=client_ip,
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error or "Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "is_admin": user.is_admin,
        }
    )
    refresh_token = create_refresh_token(user.id)
    
    await db.commit()
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expiration_minutes * 60,
        refresh_token=refresh_token,
        user=UserInfo(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_admin=user.is_admin,
        ),
    )


@router.post("/login/json", response_model=LoginResponse)
@rate_limiter.limit(auth_rate_limit)
async def login_json(
    request: Request,
    response: Response, 
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user with JSON body (alternative to form data).
    
    - **email**: User email address
    - **password**: User password
    - **remember_me**: Extend token expiration (optional)
    """
    client_ip = get_client_ip(request)
    
    user, error = await user_crud.authenticate_user(
        db,
        email=login_data.email,
        password=login_data.password,
        client_ip=client_ip,
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error or "Invalid email or password",
        )
    
    # Extend expiration if remember_me
    expires_delta = None
    if login_data.remember_me:
        expires_delta = timedelta(days=7)
    
    # Create tokens
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "is_admin": user.is_admin,
        },
        expires_delta=expires_delta,
    )
    refresh_token = create_refresh_token(
        user.id,
        expires_delta=timedelta(days=14) if login_data.remember_me else None,
    )
    
    await db.commit()
    
    expiry_minutes = settings.jwt_expiration_minutes
    if login_data.remember_me:
        expiry_minutes = 7 * 24 * 60  # 7 days
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expiry_minutes * 60,
        refresh_token=refresh_token,
        user=UserInfo(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_admin=user.is_admin,
        ),
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    
    - **refresh_token**: Valid refresh token
    """
    user_id = decode_refresh_token(refresh_data.refresh_token)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    user = await user_crud.get_user(db, user_id)
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    # Create new access token
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "is_admin": user.is_admin,
        }
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expiration_minutes * 60,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Logout user and invalidate session.
    
    Note: With JWT, token invalidation is client-side.
    Server maintains a blacklist for critical invalidations.
    """
    client_ip = get_client_ip(request)
    
    log_security_event(
        "logout",
        "User logged out",
        client_ip=client_ip,
        user_email=current_user.email,
    )
    
    return LogoutResponse(message="Successfully logged out")


@router.get("/me", response_model=CurrentUserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
):
    """
    Get current authenticated user information.
    """
    return CurrentUserResponse.model_validate(current_user)


@router.put("/me/password")
async def update_password(
    password_data: UserPasswordUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update current user's password.
    
    - **current_password**: Current password for verification
    - **new_password**: New password (min 8 characters)
    """
    from app.core.security import verify_password
    
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    
    # Update password
    await user_crud.update_user_password(db, current_user.id, password_data.new_password)
    await db.commit()
    
    return {"message": "Password updated successfully"}


# ============================================================================
# API Key Management
# ============================================================================

@router.post("/api-keys", response_model=UserAPIKeyCreatedResponse)
async def create_api_key(
    key_data: UserAPIKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new API key for the current user.
    
    **Note**: The full API key is only shown once after creation.
    Store it securely as it cannot be retrieved later.
    """
    api_key, raw_key = await user_crud.create_api_key(
        db,
        user_id=current_user.id,
        name=key_data.name,
        expires_in_days=key_data.expires_in_days,
        scopes=key_data.scopes,
        rate_limit=key_data.rate_limit,
    )
    await db.commit()
    
    response = UserAPIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        api_key=raw_key,
        is_active=api_key.is_active,
        expires_at=api_key.expires_at,
        last_used=api_key.last_used,
        usage_count=api_key.usage_count,
        rate_limit=api_key.rate_limit,
        scopes=api_key.get_scopes(),
        created_at=api_key.created_at,
    )
    
    return response


@router.get("/api-keys", response_model=list[UserAPIKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List all API keys for the current user.
    """
    api_keys = await user_crud.get_user_api_keys(db, current_user.id)
    return [UserAPIKeyResponse.model_validate(key) for key in api_keys]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke (delete) an API key.
    """
    success = await user_crud.revoke_api_key(db, key_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    await db.commit()
    return {"message": "API key revoked successfully"}


# ============================================================================
# Admin-only User Management
# ============================================================================

@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new user (admin only).
    """
    try:
        user = await user_crud.create_user(db, user_data)
        await db.commit()
        return UserResponse.model_validate(user)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    include_inactive: bool = False,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List all users (admin only).
    """
    users, total = await user_crud.get_users(
        db,
        skip=skip,
        limit=limit,
        include_inactive=include_inactive,
    )
    return [UserResponse.model_validate(user) for user in users]


@router.delete("/users/{user_id}")
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Deactivate a user (admin only).
    """
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )
    
    success = await user_crud.delete_user(db, user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    await db.commit()
    return {"message": "User deactivated successfully"}
