"""
Cyber Atlas - IOC Schemas

Pydantic schemas for IOC data validation and serialization.
"""

from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator, ConfigDict


# Valid IOC types
IOCType = Literal["ip", "cidr", "domain", "url", "hash", "email"]


class IOCBase(BaseModel):
    """Base schema for IOC data."""
    
    type: IOCType = Field(..., description="Type of IOC")
    value: str = Field(..., min_length=1, max_length=512, description="IOC value")
    source: str = Field(..., min_length=1, max_length=64, description="Source feed name")
    first_seen: Optional[datetime] = Field(None, description="First observation timestamp")
    last_seen: Optional[datetime] = Field(None, description="Last observation timestamp")
    country: Optional[str] = Field(None, max_length=8, description="Country code")
    risk: Optional[int] = Field(None, ge=1, le=10, description="Risk score (1-10)")
    notes: Optional[str] = Field(None, max_length=1024, description="Additional notes")
    tags: Optional[List[str]] = Field(None, description="List of tags")
    malware_family: Optional[str] = Field(None, max_length=128, description="Malware family")
    confidence: Optional[int] = Field(None, ge=1, le=100, description="Confidence level (1-100)")
    
    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Strip whitespace from value."""
        return v.strip()
    
    @field_validator("country")
    @classmethod
    def validate_country(cls, v: Optional[str]) -> Optional[str]:
        """Normalize country code to uppercase."""
        if v:
            return v.upper().strip()
        return v


class IOCCreate(IOCBase):
    """Schema for creating a new IOC."""
    
    raw: Optional[str] = Field(None, max_length=4000, description="Raw source data")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "ip",
                "value": "192.168.1.1",
                "source": "ThreatFox",
                "risk": 8,
                "country": "US",
                "notes": "Associated with malware distribution",
                "tags": ["malware", "c2"],
                "malware_family": "Emotet",
                "confidence": 85
            }
        }
    )


class IOCUpdate(BaseModel):
    """Schema for updating an existing IOC."""
    
    risk: Optional[int] = Field(None, ge=1, le=10, description="Risk score (1-10)")
    notes: Optional[str] = Field(None, max_length=1024, description="Additional notes")
    tags: Optional[List[str]] = Field(None, description="List of tags")
    confidence: Optional[int] = Field(None, ge=1, le=100, description="Confidence level")
    last_seen: Optional[datetime] = Field(None, description="Last observation timestamp")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "risk": 9,
                "notes": "Updated threat assessment",
                "confidence": 95
            }
        }
    )


class IOCResponse(BaseModel):
    """Schema for IOC response."""
    
    id: int
    type: str
    value: str
    source: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    country: Optional[str] = None
    risk: Optional[int] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    malware_family: Optional[str] = None
    confidence: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
    
    @field_validator("tags", mode="before")
    @classmethod
    def parse_tags(cls, v):
        """Parse comma-separated tags string to list."""
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v


class IOCListResponse(BaseModel):
    """Schema for paginated IOC list response."""
    
    items: List[IOCResponse]
    total: int = Field(..., description="Total number of matching IOCs")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, le=100, description="Items per page")
    pages: int = Field(..., ge=0, description="Total number of pages")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [],
                "total": 1250,
                "page": 1,
                "page_size": 50,
                "pages": 25
            }
        }
    )


class IOCSearchParams(BaseModel):
    """Schema for IOC search parameters."""
    
    q: Optional[str] = Field(None, max_length=512, description="Search query")
    type: Optional[IOCType] = Field(None, description="Filter by IOC type")
    source: Optional[str] = Field(None, max_length=64, description="Filter by source")
    country: Optional[str] = Field(None, max_length=8, description="Filter by country code")
    risk_min: Optional[int] = Field(None, ge=1, le=10, description="Minimum risk score")
    risk_max: Optional[int] = Field(None, ge=1, le=10, description="Maximum risk score")
    malware_family: Optional[str] = Field(None, max_length=128, description="Filter by malware family")
    first_seen_after: Optional[datetime] = Field(None, description="First seen after this date")
    first_seen_before: Optional[datetime] = Field(None, description="First seen before this date")
    last_seen_after: Optional[datetime] = Field(None, description="Last seen after this date")
    last_seen_before: Optional[datetime] = Field(None, description="Last seen before this date")
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(50, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field("last_seen", description="Sort field")
    sort_order: Literal["asc", "desc"] = Field("desc", description="Sort order")
    
    @field_validator("country")
    @classmethod
    def validate_country(cls, v: Optional[str]) -> Optional[str]:
        """Normalize country code to uppercase."""
        if v:
            return v.upper().strip()
        return v


class IOCStats(BaseModel):
    """Schema for IOC statistics."""
    
    total_count: int = Field(..., description="Total number of IOCs")
    by_type: dict[str, int] = Field(..., description="Count by IOC type")
    by_source: dict[str, int] = Field(..., description="Count by source")
    by_country: dict[str, int] = Field(..., description="Count by country")
    by_risk: dict[int, int] = Field(..., description="Count by risk level")
    last_updated: datetime = Field(..., description="Last update timestamp")


class IOCTimeline(BaseModel):
    """Schema for IOC timeline data."""
    
    date: str = Field(..., description="Date string (YYYY-MM-DD)")
    count: int = Field(..., description="Number of IOCs for this date")
    by_type: Optional[dict[str, int]] = Field(None, description="Count by type for this date")


class IOCBulkCreate(BaseModel):
    """Schema for bulk IOC creation."""
    
    iocs: List[IOCCreate] = Field(..., min_length=1, max_length=1000, description="List of IOCs to create")
    skip_duplicates: bool = Field(True, description="Skip duplicate IOCs instead of erroring")


class IOCBulkResponse(BaseModel):
    """Schema for bulk operation response."""
    
    created: int = Field(..., description="Number of IOCs created")
    skipped: int = Field(..., description="Number of IOCs skipped (duplicates)")
    errors: int = Field(..., description="Number of errors")
    error_details: Optional[List[str]] = Field(None, description="Error details")
