"""
storage.py — MinIO S3-compatible object storage layer for TrustVault.
"""

import os
import logging
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

logger = logging.getLogger(__name__)

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ROOT_USER", "admin")
MINIO_SECRET_KEY = os.getenv("MINIO_ROOT_PASSWORD", "StrongPassword123")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "trustvault")
USE_MINIO = os.getenv("USE_MINIO", "true").lower() == "true"

LOCAL_UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)


def _get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(
            signature_version="s3v4",
            connect_timeout=5,
            read_timeout=30,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
        region_name="us-east-1",
    )


def _ensure_bucket(s3_client):
    try:
        s3_client.head_bucket(Bucket=MINIO_BUCKET)
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            s3_client.create_bucket(Bucket=MINIO_BUCKET)
            logger.info(f"Created MinIO bucket: {MINIO_BUCKET}")
        else:
            raise


class StorageBackend:

    def __init__(self):
        self._minio_available = False
        self._s3 = None
        if USE_MINIO:
            self._init_minio()

    def _init_minio(self):
        try:
            self._s3 = _get_s3_client()
            _ensure_bucket(self._s3)
            self._minio_available = True
            logger.info(f"✅ MinIO connected: {MINIO_ENDPOINT} / bucket={MINIO_BUCKET}")
        except Exception as e:
            logger.warning(f"⚠️  MinIO unavailable ({e}). Falling back to local disk.")
            self._minio_available = False

    @property
    def backend_name(self) -> str:
        return "MinIO" if self._minio_available else "LocalDisk"

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> bool:
        if self._minio_available:
            try:
                self._s3.put_object(
                    Bucket=MINIO_BUCKET,
                    Key=key,
                    Body=data,
                    ContentType=content_type,
                    Metadata={"encrypted": "AES-256-GCM"},
                )
                return True
            except Exception as e:
                logger.error(f"MinIO PUT failed for {key}: {e}. Falling back to disk.")

        try:
            path = os.path.join(LOCAL_UPLOAD_DIR, key)
            with open(path, "wb") as f:
                f.write(data)
            return True
        except Exception as e:
            logger.error(f"LocalDisk PUT failed for {key}: {e}")
            return False

    def get(self, key: str):
        if self._minio_available:
            try:
                response = self._s3.get_object(Bucket=MINIO_BUCKET, Key=key)
                return response["Body"].read()
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                    logger.error(f"MinIO GET failed for {key}: {e}")
            except Exception as e:
                logger.error(f"MinIO GET error for {key}: {e}")

        path = os.path.join(LOCAL_UPLOAD_DIR, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        return None

    def delete(self, key: str) -> bool:
        if self._minio_available:
            try:
                self._s3.delete_object(Bucket=MINIO_BUCKET, Key=key)
            except Exception as e:
                logger.error(f"MinIO DELETE failed for {key}: {e}")

        path = os.path.join(LOCAL_UPLOAD_DIR, key)
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                logger.error(f"LocalDisk DELETE failed for {key}: {e}")
        return True

    def exists(self, key: str) -> bool:
        if self._minio_available:
            try:
                self._s3.head_object(Bucket=MINIO_BUCKET, Key=key)
                return True
            except Exception:
                pass
        return os.path.exists(os.path.join(LOCAL_UPLOAD_DIR, key))

    def get_stats(self) -> dict:
        stats = {
            "backend": self.backend_name,
            "minio_endpoint": MINIO_ENDPOINT if self._minio_available else None,
        }
        if self._minio_available:
            try:
                paginator = self._s3.get_paginator("list_objects_v2")
                total_size = 0
                total_objects = 0
                for page in paginator.paginate(Bucket=MINIO_BUCKET):
                    for obj in page.get("Contents", []):
                        total_size += obj["Size"]
                        total_objects += 1
                stats["objects"] = total_objects
                stats["total_mb"] = round(total_size / (1024 * 1024), 2)
            except Exception as e:
                stats["error"] = str(e)
        else:
            total_size = 0
            count = 0
            for fname in os.listdir(LOCAL_UPLOAD_DIR):
                fpath = os.path.join(LOCAL_UPLOAD_DIR, fname)
                if os.path.isfile(fpath):
                    total_size += os.path.getsize(fpath)
                    count += 1
            stats["objects"] = count
            stats["total_mb"] = round(total_size / (1024 * 1024), 2)
        return stats

    def get_health(self) -> dict:
        if not USE_MINIO:
            return {"status": "local_disk", "message": "MinIO disabled"}
        if self._minio_available:
            try:
                self._s3.head_bucket(Bucket=MINIO_BUCKET)
                return {"status": "healthy", "backend": "MinIO", "endpoint": MINIO_ENDPOINT}
            except Exception as e:
                return {"status": "degraded", "backend": "MinIO", "error": str(e)}
        return {"status": "fallback", "backend": "LocalDisk"}


# Singleton
storage = StorageBackend()