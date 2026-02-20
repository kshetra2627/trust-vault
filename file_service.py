"""
file_service.py — Helper utilities for file type detection.

Note: The actual file saving, encryption, and deduplication logic lives
in main.py so it can access the DB session and current user directly.
This module provides shared utilities used across the project.
"""
import os
import hashlib

UPLOAD_DIR = "uploads"
CHUNKS_DIR = "chunks"

# Extension → MIME type map (avoids python-magic cross-platform issues)
MIME_MAP = {
    "pdf":  "application/pdf",
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
    "gif":  "image/gif",
    "webp": "image/webp",
    "txt":  "text/plain",
    "md":   "text/markdown",
    "csv":  "text/csv",
    "json": "application/json",
    "xml":  "application/xml",
    "zip":  "application/zip",
    "tar":  "application/x-tar",
    "gz":   "application/gzip",
    "mp4":  "video/mp4",
    "mp3":  "audio/mpeg",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def detect_mime(filename: str) -> str:
    """Detect MIME type from file extension."""
    if "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        return MIME_MAP.get(ext, "application/octet-stream")
    return "application/octet-stream"


def ensure_dirs():
    """Create upload and chunk directories if they don't exist."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(CHUNKS_DIR, exist_ok=True)


def file_exists_on_disk(file_hash: str) -> bool:
    """Check if encrypted file is present on disk."""
    return os.path.exists(os.path.join(UPLOAD_DIR, file_hash))


def get_storage_stats() -> dict:
    """Return disk usage stats for uploads directory."""
    ensure_dirs()
    total_size = 0
    file_count = 0
    for fname in os.listdir(UPLOAD_DIR):
        fpath = os.path.join(UPLOAD_DIR, fname)
        if os.path.isfile(fpath):
            total_size += os.path.getsize(fpath)
            file_count += 1
    return {
        "files_on_disk": file_count,
        "total_disk_bytes": total_size,
        "total_disk_mb": round(total_size / (1024 * 1024), 2),
    }