"""
Cyber Atlas - User Schemas

Pydantic schemas for User data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, field_validator, ConfigDict


class UserBase(BaseModel):
    """Base schema for User data."""
    
    email: EmailStr = Field(..., description="User email address")
    full_name: Optional[str] = Field(None, max_length=255, description="User's full name")


class UserCreate(UserBase):
    """Schema for creating a new user."""
    
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password (min 8 characters)"
    )
    is_admin: bool = Field(False, description="Whether user has admin privileges")
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!",
                "full_name": "John Doe",
                "is_admin": False
            }
        }
    )


class UserUpdate(BaseModel):
    """Schema for updating an existing user."""
    
    email: Optional[EmailStr] = Field(None, description="New email address")
    full_name: Optional[str] = Field(None, max_length=255, description="New full name")
    is_active: Optional[bool] = Field(None, description="Account active status")
    is_admin: Optional[bool] = Field(None, description="Admin privileges")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "full_name": "Jane Doe",
                "is_active": True
            }
        }
    )


class UserPasswordUpdate(BaseModel):
    """Schema for updating user password."""
    
    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password"
    )
    
    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserResponse(BaseModel):
    """Schema for user response (public data only)."""
    
    id: int
    email: str
    full_name: Optional[str] = None
    is_active: bool
    is_admin: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class UserDetailResponse(UserResponse):
    """Schema for detailed user response (includes more fields)."""
    
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    updated_at: datetime


class UserListResponse(BaseModel):
    """Schema for paginated user list response."""
    
    items: List[UserResponse]
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, le=100, description="Items per page")
    pages: int = Field(..., ge=0, description="Total number of pages")


class UserSearchParams(BaseModel):
    """Schema for user search parameters."""
    
    q: Optional[str] = Field(None, max_length=255, description="Search query (email or name)")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_admin: Optional[bool] = Field(None, description="Filter by admin status")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(50, ge=1, le=100, description="Items per page")


class UserAPIKeyCreate(BaseModel):
    """Schema for creating a new API key."""
    
    name: str = Field(..., min_length=1, max_length=128, description="API key name")
    expires_in_days: Optional[int] = Field(
        None,
        ge=1,
        le=365,
        description="Days until expiration (null for no expiration)"
    )
    scopes: Optional[List[str]] = Field(None, description="Allowed scopes")
    rate_limit: Optional[int] = Field(
        None,
        ge=1,
        le=10000,
        description="Custom rate limit (requests per minute)"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "CI/CD Integration",
                "expires_in_days": 90,
                "scopes": ["read:iocs", "write:iocs"],
                "rate_limit": 1000
            }
        }
    )


class UserAPIKeyResponse(BaseModel):
    """Schema for API key response."""
    
    id: int
    name: str
    key_prefix: str
    is_active: bool
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int
    rate_limit: Optional[int] = None
    scopes: Optional[List[str]] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
    
    @field_validator("scopes", mode="before")
    @classmethod
    def parse_scopes(cls, v):
        """Parse comma-separated scopes string to list."""
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v


class UserAPIKeyCreatedResponse(UserAPIKeyResponse):
    """Schema for newly created API key (includes full key)."""
    
    api_key: str = Field(..., description="Full API key (shown only once)")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 1,
                "name": "CI/CD Integration",
                "key_prefix": "ca_abc123",
                "api_key": "ca_abc123def456...",
                "is_active": True,
                "expires_at": None,
                "created_at": "2024-01-12T00:00:00Z"
            }
        }
    )
