from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    data_region: Optional[str] = "EU"


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class FileOut(BaseModel):
    id: int
    filename: str
    file_hash: str
    size: int
    mime_type: Optional[str]
    version: int
    is_latest: bool
    data_region: str
    uploaded_at: Optional[str]


class ChunkSessionCreate(BaseModel):
    filename: str
    total_chunks: int
    chunk_size: int
    total_size: int
    expected_hash: Optional[str] = None  # optional client-provided expected final hash


class ShareFileRequest(BaseModel):
    file_id: int
    target_username: str
    can_read: bool = True
    can_write: bool = False
    can_delete: bool = False
    expires_at: Optional[datetime] = None


class ChangeRoleRequest(BaseModel):
    username: str
    role: str  # "admin" | "user" | "readonly"