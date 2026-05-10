"""
Cyber Atlas - Authentication Schemas

Pydantic schemas for authentication and authorization.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr, ConfigDict


class Token(BaseModel):
    """Schema for JWT token response."""
    
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token for obtaining new access tokens")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400,
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    )


class TokenPayload(BaseModel):
    """Schema for JWT token payload."""
    
    sub: str = Field(..., description="Subject (user ID)")
    email: str = Field(..., description="User email")
    is_admin: bool = Field(False, description="Admin status")
    exp: datetime = Field(..., description="Expiration timestamp")
    iat: datetime = Field(..., description="Issued at timestamp")
    type: str = Field(..., description="Token type (access/refresh)")


class LoginRequest(BaseModel):
    """Schema for login request."""
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(False, description="Extend token expiration")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "admin@cyberatlas.local",
                "password": "YourSecurePassword123!",
                "remember_me": False
            }
        }
    )


class LoginResponse(BaseModel):
    """Schema for login response."""
    
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    user: "UserInfo" = Field(..., description="User information")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400,
                "user": {
                    "id": 1,
                    "email": "admin@cyberatlas.local",
                    "full_name": "Admin User",
                    "is_admin": True
                }
            }
        }
    )


class UserInfo(BaseModel):
    """Schema for basic user information in auth responses."""
    
    id: int = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="User's full name")
    is_admin: bool = Field(..., description="Admin status")
    
    model_config = ConfigDict(from_attributes=True)


class RefreshTokenRequest(BaseModel):
    """Schema for token refresh request."""
    
    refresh_token: str = Field(..., description="Refresh token")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    )


class LogoutRequest(BaseModel):
    """Schema for logout request."""
    
    refresh_token: Optional[str] = Field(None, description="Refresh token to invalidate")


class LogoutResponse(BaseModel):
    """Schema for logout response."""
    
    message: str = Field(default="Successfully logged out", description="Logout message")


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""
    
    email: EmailStr = Field(..., description="User email address")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com"
            }
        }
    )


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""
    
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "reset_token_here",
                "new_password": "NewSecurePass123!"
            }
        }
    )


class CurrentUserResponse(BaseModel):
    """Schema for current user information."""
    
    id: int
    email: str
    full_name: Optional[str] = None
    is_active: bool
    is_admin: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class APIKeyAuthHeader(BaseModel):
    """Schema for API key authentication header."""
    
    x_api_key: str = Field(..., alias="X-API-Key", description="API key for authentication")


# Update forward reference
LoginResponse.model_rebuild()
