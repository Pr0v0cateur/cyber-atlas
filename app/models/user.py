"""
Cyber Atlas - User Model

Database model for user authentication and authorization.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.database import Base


class User(Base):
    """
    User database model for authentication.
    
    Attributes:
        id: Primary key
        email: Unique email address (used for login)
        hashed_password: Bcrypt hashed password
        full_name: User's full name
        is_active: Whether the user account is active
        is_admin: Whether the user has admin privileges
        last_login: Timestamp of last successful login
        failed_login_attempts: Counter for failed login attempts
        locked_until: Timestamp until which the account is locked
        created_at: Record creation timestamp
        updated_at: Record last update timestamp
    """
    
    __tablename__ = "users"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Authentication fields
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
        comment="Unique email address"
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # Profile fields
    full_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="User's full name"
    )
    
    # Status flags
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the account is active"
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the user has admin privileges"
    )
    
    # Security tracking
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful login timestamp"
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of consecutive failed login attempts"
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Account locked until this timestamp"
    )
    
    # Record timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Record creation timestamp"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="Record last update timestamp"
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', is_admin={self.is_admin})>"
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert User to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
        
        Returns:
            Dictionary representation of the user
        """
        data = {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        
        if include_sensitive:
            data.update({
                "failed_login_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until.isoformat() if self.locked_until else None,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            })
        
        return data
    
    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.now(self.locked_until.tzinfo) < self.locked_until
    
    def can_login(self) -> tuple[bool, str]:
        """
        Check if the user can login.
        
        Returns:
            Tuple of (can_login, reason)
        """
        if not self.is_active:
            return False, "Account is deactivated"
        
        if self.is_locked():
            return False, f"Account is locked until {self.locked_until}"
        
        return True, ""
