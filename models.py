from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Text, Boolean, ForeignKey, LargeBinary
from sqlalchemy.sql import func
from database import Base
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# User Model
# ─────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    email = Column(String, unique=True)
    role = Column(String, default="user")  # admin | user | readonly
    is_active = Column(Boolean, default=True)
    failed_logins = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    data_region = Column(String, default="EU")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────────────────────
# File Model
# ─────────────────────────────────────────────────────────────
class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    file_hash = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    size = Column(BigInteger)
    mime_type = Column(String)
    encryption_key = Column(Text)
    reference_count = Column(Integer, default=1)
    version = Column(Integer, default=1)
    is_latest = Column(Boolean, default=True)
    is_deleted = Column(Boolean, default=False)
    data_region = Column(String, default="EU")
    checksum_sha256 = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────────────────────
# File Permissions
# ─────────────────────────────────────────────────────────────
class FilePermission(Base):
    __tablename__ = "file_permissions"

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    granted_by = Column(Integer, ForeignKey("users.id"))
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)


# ─────────────────────────────────────────────────────────────
# Chunk Upload Sessions
# ─────────────────────────────────────────────────────────────
class ChunkUploadSession(Base):
    __tablename__ = "chunk_upload_sessions"

    id = Column(String, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String)
    total_chunks = Column(Integer)
    uploaded_chunks = Column(Integer, default=0)
    received_chunk_indices = Column(Text, default="")
    chunk_size = Column(Integer)
    total_size = Column(BigInteger)
    expected_hash = Column(String, nullable=True)
    status = Column(String, default="in_progress")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    entry_id = Column(String, unique=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = Column(String)
    action = Column(String)
    file_hash = Column(String, nullable=True)
    meta_data = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    previous_hash = Column(String)
    current_hash = Column(String, unique=True)


# ─────────────────────────────────────────────────────────────
# Secure File Share (Use THIS Instead of SharedFile)
# ─────────────────────────────────────────────────────────────
class FileShare(Base):
    __tablename__ = "file_shares"

    token = Column(String, primary_key=True, index=True)
    file_hash = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    sender_username = Column(String, nullable=False, index=True)
    recipient_username = Column(String, nullable=False, index=True)
    share_encrypted_data = Column(LargeBinary, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)