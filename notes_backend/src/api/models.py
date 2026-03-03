from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Human-readable error message.")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address (unique, case-insensitive).")
    password: str = Field(..., min_length=8, max_length=128, description="User password (min 8 chars).")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address.")
    password: str = Field(..., min_length=1, max_length=128, description="User password.")


class AuthResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token (Bearer).")
    token_type: str = Field("bearer", description="Token type.")
    user_id: UUID = Field(..., description="Authenticated user's ID.")
    email: EmailStr = Field(..., description="Authenticated user's email.")


class UserMeResponse(BaseModel):
    id: UUID = Field(..., description="User ID.")
    email: EmailStr = Field(..., description="User email.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp (if any).")


class NoteCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Note title.")
    content: str = Field(..., min_length=1, max_length=20000, description="Note content.")
    is_archived: bool = Field(False, description="Whether the note is archived.")


class NoteUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200, description="Updated title.")
    content: Optional[str] = Field(None, min_length=1, max_length=20000, description="Updated content.")
    is_archived: Optional[bool] = Field(None, description="Updated archived flag.")


class NoteResponse(BaseModel):
    id: UUID = Field(..., description="Note ID.")
    user_id: UUID = Field(..., description="Owner user ID.")
    title: str = Field(..., description="Note title.")
    content: str = Field(..., description="Note content.")
    is_archived: bool = Field(..., description="Archived flag.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Update timestamp.")


class NotesListResponse(BaseModel):
    items: list[NoteResponse] = Field(..., description="Notes page items.")
    total: int = Field(..., ge=0, description="Total matching notes count.")
    limit: int = Field(..., ge=1, le=100, description="Page size.")
    offset: int = Field(..., ge=0, description="Offset into results.")
