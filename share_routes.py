# share_routes.py

import io
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import os

from database import get_db
from secure_share import (
    generate_share_password,
    encrypt_for_share,
    decrypt_from_share,
    verify_share_password,
)
from storage import storage

router = APIRouter(prefix="/share", tags=["Secure Sharing"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ─── AUTH ─────────────────────────────────────────────

def _get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    import models
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production-minimum-32-chars!")
    exc = HTTPException(status_code=401, detail="Invalid or expired token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise exc

    return user


# ─── SCHEMAS ─────────────────────────────────────────────

class CreateShareRequest(BaseModel):
    file_hash: str
    filename: str
    recipient_username: str
    expires_hours: int = 24
    custom_password: Optional[str] = None


class CreateShareResponse(BaseModel):
    share_token: str
    share_password: str
    download_url: str
    expires_at: str
    message: str


# ─── CREATE SHARE ─────────────────────────────────────

@router.post("/create", response_model=CreateShareResponse)
def create_share(
    req: CreateShareRequest,
    db: Session = Depends(get_db),
    current_user=Depends(_get_current_user),
):
    encrypted_data = storage.get(req.file_hash)
    if encrypted_data is None:
        raise HTTPException(status_code=404, detail="File not found in storage.")

    password = req.custom_password.strip() if req.custom_password else generate_share_password(16)

    share_encrypted = encrypt_for_share(encrypted_data, password)

    import models
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=req.expires_hours)

    share = models.FileShare(
        token=token,
        file_hash=req.file_hash,
        filename=req.filename,
        sender_username=current_user.username,
        recipient_username=req.recipient_username,
        share_encrypted_data=share_encrypted,
        expires_at=expires_at,
        is_active=True,
    )

    db.add(share)
    db.commit()

    download_url = f"/share/download/{token}"

    return CreateShareResponse(
        share_token=token,
        share_password=password,
        download_url=download_url,
        expires_at=expires_at.isoformat(),
        message="Share created successfully.",
    )


# ─── DOWNLOAD ─────────────────────────────────────────

@router.get("/download/{token}")
def download_shared_file(
    token: str,
    password: str = Query(...),
    db: Session = Depends(get_db),
):
    import models

    share = db.query(models.FileShare).filter(models.FileShare.token == token).first()
    if not share:
        raise HTTPException(status_code=404, detail="Share link not found.")

    if datetime.utcnow() > share.expires_at:
        raise HTTPException(status_code=410, detail="Share expired.")

    if not share.is_active:
        raise HTTPException(status_code=410, detail="Share revoked.")

    if not verify_share_password(share.share_encrypted_data, password):
        raise HTTPException(status_code=403, detail="Wrong password.")

    decrypted_data = decrypt_from_share(share.share_encrypted_data, password)

    return StreamingResponse(
        io.BytesIO(decrypted_data),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{share.filename}"'
        },
    )