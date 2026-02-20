from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Request, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timezone
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import os
import uuid
import io

# ─── App created FIRST before any include_router ─────────────────────────────
app = FastAPI(
    title="TrustVault API",
    description="Zero-Trust GDPR-Compliant Secure Cloud Storage",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Register share router ────────────────────────────────────────────────────
from share_routes import router as share_router
app.include_router(share_router)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

from database import Base, engine, get_db
import models, schemas
from security import hash_password, verify_password
from auth import create_access_token, SECRET_KEY, ALGORITHM
from encryption import encrypt_file_data, decrypt_file_data, verify_file_integrity
from audit import create_audit_entry, verify_audit_chain

Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

UPLOAD_DIR = "uploads"
CHUNKS_DIR = "chunks"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CHUNKS_DIR, exist_ok=True)

MAX_FAILED_LOGINS = 5


# ─── Global exception handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {str(exc)}"}
    )


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    exc = HTTPException(status_code=401, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise exc

    if user.locked_until and datetime.now(timezone.utc) < user.locked_until.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=423, detail="Account temporarily locked")

    return user


def require_admin(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0] if forwarded else request.client.host


# ─── Root & Health ────────────────────────────────────────────────────────────

@app.get("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(index_path):
        return JSONResponse(status_code=200, content={"message": "TrustVault API is running."})
    return FileResponse(index_path)


@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "service": "TrustVault", "version": "2.0.0"}


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.post("/register", tags=["Auth"])
def register(user: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    db_user = models.User(
        username=user.username,
        password_hash=hash_password(user.password),
        email=user.email,
        data_region=user.data_region or "EU",
    )
    db.add(db_user)
    db.commit()

    create_audit_entry(db, "USER_REGISTERED", user=user.username, ip_address=get_client_ip(request))
    return {"message": "User registered successfully", "data_region": db_user.data_region}


@app.post("/login", response_model=schemas.Token, tags=["Auth"])
def login(user: schemas.UserLogin, request: Request, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()

    if db_user and db_user.locked_until:
        if datetime.now(timezone.utc) < db_user.locked_until.replace(tzinfo=timezone.utc):
            raise HTTPException(status_code=423, detail="Account locked. Try again later.")

    if not db_user or not verify_password(user.password, db_user.password_hash):
        if db_user:
            db_user.failed_logins = (db_user.failed_logins or 0) + 1
            if db_user.failed_logins >= MAX_FAILED_LOGINS:
                from datetime import timedelta
                db_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.commit()
        create_audit_entry(db, "LOGIN_FAILED", user=user.username, ip_address=get_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid credentials")

    db_user.failed_logins = 0
    db_user.locked_until = None
    db.commit()

    token = create_access_token({"sub": db_user.username, "role": db_user.role})
    create_audit_entry(db, "USER_LOGIN", user=user.username, ip_address=get_client_ip(request))
    return {"access_token": token, "token_type": "bearer"}


# ─── Upload ───────────────────────────────────────────────────────────────────

@app.post("/upload", tags=["Files"])
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == "readonly":
        raise HTTPException(status_code=403, detail="Read-only users cannot upload files")

    content = file.file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    mime_type = file.content_type or "application/octet-stream"

    existing = db.query(models.File).filter(
        models.File.file_hash == file_hash,
        models.File.is_deleted == False
    ).first()

    if existing:
        existing.reference_count = (existing.reference_count or 1) + 1
        db.commit()
        create_audit_entry(db, "FILE_DEDUPLICATED", user=current_user.username,
                           file_hash=file_hash, ip_address=get_client_ip(request))
        return {"message": "Deduplicated — file already exists", "file_hash": file_hash,
                "deduplication": True, "encryption": "AES-256-GCM"}

    latest = db.query(models.File).filter(
        models.File.owner_id == current_user.id,
        models.File.filename == file.filename,
        models.File.is_latest == True,
        models.File.is_deleted == False
    ).first()

    next_version = 1
    if latest:
        next_version = latest.version + 1
        latest.is_latest = False
        db.commit()

    encrypted_data, encryption_key, checksum = encrypt_file_data(content)
    filepath = os.path.join(UPLOAD_DIR, file_hash)
    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    db_file = models.File(
        filename=file.filename,
        file_hash=file_hash,
        owner_id=current_user.id,
        size=len(content),
        mime_type=mime_type,
        encryption_key=encryption_key,
        checksum_sha256=checksum,
        reference_count=1,
        version=next_version,
        is_latest=True,
        data_region=current_user.data_region,
    )
    db.add(db_file)
    db.commit()

    create_audit_entry(db, "FILE_UPLOADED", user=current_user.username,
                       file_hash=file_hash, ip_address=get_client_ip(request),
                       meta_data=f"version={next_version},size={len(content)}")

    return {
        "message": "File uploaded and encrypted",
        "file_hash": file_hash,
        "size": len(content),
        "version": next_version,
        "deduplication": False,
        "encryption": "AES-256-GCM",
        "data_region": current_user.data_region,
    }


# ─── Chunked Upload ───────────────────────────────────────────────────────────

@app.post("/upload/session", tags=["Resumable Upload"])
def create_upload_session(
    session_req: schemas.ChunkSessionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if current_user.role == "readonly":
        raise HTTPException(status_code=403, detail="Read-only users cannot upload")

    session_id = str(uuid.uuid4())
    session = models.ChunkUploadSession(
        id=session_id,
        owner_id=current_user.id,
        filename=session_req.filename,
        total_chunks=session_req.total_chunks,
        chunk_size=session_req.chunk_size,
        total_size=session_req.total_size,
        expected_hash=session_req.expected_hash,
    )
    db.add(session)
    db.commit()
    create_audit_entry(db, "CHUNK_SESSION_STARTED", user=current_user.username,
                       meta_data=f"session={session_id},chunks={session_req.total_chunks}")
    return {"session_id": session_id, "total_chunks": session_req.total_chunks}


@app.post("/upload/chunk/{session_id}", tags=["Resumable Upload"])
def upload_chunk(
    session_id: str,
    chunk_index: int = Query(...),
    chunk: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    session = db.query(models.ChunkUploadSession).filter(
        models.ChunkUploadSession.id == session_id,
        models.ChunkUploadSession.owner_id == current_user.id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Upload session not found")
    if session.status == "complete":
        return {"message": "Session already complete"}

    chunk_data = chunk.file.read()
    chunk_path = os.path.join(CHUNKS_DIR, f"{session_id}_chunk_{chunk_index}")
    received = set(session.received_chunk_indices.split(",")) if session.received_chunk_indices else set()

    if str(chunk_index) not in received:
        with open(chunk_path, "wb") as f:
            f.write(chunk_data)
        received.add(str(chunk_index))
        session.received_chunk_indices = ",".join(received)
        session.uploaded_chunks = len(received)
        db.commit()

    if session.uploaded_chunks >= session.total_chunks:
        return _assemble_chunks(session_id, session, db, current_user)

    return {"message": f"Chunk {chunk_index} received",
            "uploaded": session.uploaded_chunks, "total": session.total_chunks}


@app.get("/upload/session/{session_id}", tags=["Resumable Upload"])
def get_upload_status(session_id: str, db: Session = Depends(get_db),
                      current_user: models.User = Depends(get_current_user)):
    session = db.query(models.ChunkUploadSession).filter(
        models.ChunkUploadSession.id == session_id,
        models.ChunkUploadSession.owner_id == current_user.id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    received = set(session.received_chunk_indices.split(",")) if session.received_chunk_indices else set()
    return {
        "session_id": session_id, "filename": session.filename, "status": session.status,
        "uploaded_chunks": session.uploaded_chunks, "total_chunks": session.total_chunks,
        "received_indices": sorted([int(x) for x in received if x]),
        "missing_indices": [i for i in range(session.total_chunks) if str(i) not in received],
    }


def _assemble_chunks(session_id, session, db, current_user):
    chunks = []
    for i in range(session.total_chunks):
        path = os.path.join(CHUNKS_DIR, f"{session_id}_chunk_{i}")
        if not os.path.exists(path):
            raise HTTPException(status_code=409, detail=f"Chunk {i} missing")
        with open(path, "rb") as f:
            chunks.append(f.read())

    content = b"".join(chunks)
    file_hash = hashlib.sha256(content).hexdigest()

    if session.expected_hash and session.expected_hash != file_hash:
        session.status = "failed"
        db.commit()
        raise HTTPException(status_code=422, detail="Integrity check FAILED")

    encrypted_data, encryption_key, checksum = encrypt_file_data(content)
    with open(os.path.join(UPLOAD_DIR, file_hash), "wb") as f:
        f.write(encrypted_data)

    latest = db.query(models.File).filter(
        models.File.owner_id == current_user.id,
        models.File.filename == session.filename,
        models.File.is_latest == True
    ).first()
    next_version = (latest.version + 1) if latest else 1
    if latest:
        latest.is_latest = False
        db.commit()

    db.add(models.File(
        filename=session.filename, file_hash=file_hash, owner_id=current_user.id,
        size=len(content), mime_type="application/octet-stream",
        encryption_key=encryption_key, checksum_sha256=checksum,
        version=next_version, is_latest=True, data_region=current_user.data_region,
    ))
    session.status = "complete"
    db.commit()

    for i in range(session.total_chunks):
        p = os.path.join(CHUNKS_DIR, f"{session_id}_chunk_{i}")
        if os.path.exists(p):
            os.remove(p)

    create_audit_entry(db, "CHUNKED_UPLOAD_COMPLETE", user=current_user.username,
                       file_hash=file_hash, meta_data=f"version={next_version}")
    return {"message": "Assembled and stored", "file_hash": file_hash,
            "version": next_version, "encryption": "AES-256-GCM"}


# ─── Download ─────────────────────────────────────────────────────────────────

@app.get("/download/{file_hash}", tags=["Files"])
def download_file(
    file_hash: str, request: Request,
    token: str = Query(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_file = db.query(models.File).filter(
        models.File.file_hash == file_hash, models.File.is_deleted == False
    ).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    if db_file.owner_id != current_user.id:
        perm = db.query(models.FilePermission).filter(
            models.FilePermission.file_id == db_file.id,
            models.FilePermission.user_id == current_user.id,
            models.FilePermission.can_read == True
        ).first()
        if not perm:
            raise HTTPException(status_code=403, detail="Access denied")

    filepath = os.path.join(UPLOAD_DIR, file_hash)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File data not found on disk")

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    plaintext = decrypt_file_data(encrypted_data, db_file.encryption_key)

    if not verify_file_integrity(plaintext, db_file.checksum_sha256):
        create_audit_entry(db, "INTEGRITY_CHECK_FAILED", user=current_user.username,
                           file_hash=file_hash, ip_address=get_client_ip(request))
        raise HTTPException(status_code=500, detail="File integrity check FAILED")

    create_audit_entry(db, "FILE_DOWNLOADED", user=current_user.username,
                       file_hash=file_hash, ip_address=get_client_ip(request))

    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=db_file.mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{db_file.filename}"'}
    )


# ─── Files ────────────────────────────────────────────────────────────────────

@app.get("/files", tags=["Files"])
def list_files(include_versions: bool = Query(False),
               db: Session = Depends(get_db),
               current_user: models.User = Depends(get_current_user)):
    query = db.query(models.File).filter(
        models.File.owner_id == current_user.id, models.File.is_deleted == False
    )
    if not include_versions:
        query = query.filter(models.File.is_latest == True)
    return [
        {"id": f.id, "filename": f.filename, "file_hash": f.file_hash,
         "size": f.size, "mime_type": f.mime_type, "version": f.version,
         "is_latest": f.is_latest, "data_region": f.data_region,
         "uploaded_at": str(f.created_at)}
        for f in query.all()
    ]


@app.get("/files/{filename}/versions", tags=["Files"])
def get_file_versions(filename: str, db: Session = Depends(get_db),
                      current_user: models.User = Depends(get_current_user)):
    versions = db.query(models.File).filter(
        models.File.owner_id == current_user.id,
        models.File.filename == filename,
        models.File.is_deleted == False
    ).order_by(models.File.version.desc()).all()
    if not versions:
        raise HTTPException(status_code=404, detail="File not found")
    return [{"version": f.version, "file_hash": f.file_hash, "size": f.size,
             "is_latest": f.is_latest, "uploaded_at": str(f.created_at)} for f in versions]


@app.delete("/files/{file_hash}", tags=["Files"])
def delete_file(file_hash: str, request: Request,
                db: Session = Depends(get_db),
                current_user: models.User = Depends(get_current_user)):
    db_file = db.query(models.File).filter(
        models.File.file_hash == file_hash,
        models.File.owner_id == current_user.id,
        models.File.is_deleted == False
    ).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    db_file.is_deleted = True
    db.commit()
    create_audit_entry(db, "FILE_DELETED", user=current_user.username,
                       file_hash=file_hash, ip_address=get_client_ip(request))
    return {"message": "File deleted", "file_hash": file_hash}


@app.delete("/gdpr/erase-my-data", tags=["GDPR"])
def gdpr_erasure(request: Request, db: Session = Depends(get_db),
                 current_user: models.User = Depends(get_current_user)):
    files = db.query(models.File).filter(
        models.File.owner_id == current_user.id, models.File.is_deleted == False
    ).all()
    count = len(files)
    for f in files:
        f.is_deleted = True
    db.commit()
    create_audit_entry(db, "GDPR_ERASURE_REQUESTED", user=current_user.username,
                       ip_address=get_client_ip(request), meta_data=f"files_erased={count}")
    return {"message": f"GDPR erasure complete — {count} files marked for deletion"}


# ─── Sharing (original simple share) ─────────────────────────────────────────

@app.post("/files/share", tags=["Sharing"])
def share_file(share: schemas.ShareFileRequest, request: Request,
               db: Session = Depends(get_db),
               current_user: models.User = Depends(get_current_user)):
    db_file = db.query(models.File).filter(
        models.File.id == share.file_id, models.File.owner_id == current_user.id
    ).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found or you don't own it")
    target = db.query(models.User).filter(models.User.username == share.target_username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")

    db.query(models.FilePermission).filter(
        models.FilePermission.file_id == share.file_id,
        models.FilePermission.user_id == target.id
    ).delete()
    db.add(models.FilePermission(
        file_id=share.file_id, user_id=target.id,
        can_read=share.can_read, can_write=share.can_write, can_delete=share.can_delete,
        granted_by=current_user.id, expires_at=share.expires_at,
    ))
    db.commit()
    create_audit_entry(db, "FILE_SHARED", user=current_user.username,
                       file_hash=db_file.file_hash, ip_address=get_client_ip(request),
                       meta_data=f"shared_with={share.target_username}")
    return {"message": f"File shared with {share.target_username}",
            "permissions": {"read": share.can_read, "write": share.can_write, "delete": share.can_delete}}


# ─── Audit ────────────────────────────────────────────────────────────────────

@app.get("/audit-logs", tags=["Audit"])
def get_audit_logs(db: Session = Depends(get_db),
                   current_user: models.User = Depends(get_current_user)):
    if current_user.role == "admin":
        logs = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(100).all()
    else:
        logs = db.query(models.AuditLog).filter(
            models.AuditLog.user == current_user.username
        ).order_by(models.AuditLog.id.desc()).limit(100).all()
    return [{"id": l.id, "action": l.action, "user": l.user, "file_hash": l.file_hash,
             "timestamp": str(l.timestamp), "ip_address": l.ip_address,
             "current_hash": l.current_hash} for l in logs]


@app.get("/audit-logs/verify", tags=["Audit"])
def verify_audit_integrity(db: Session = Depends(get_db),
                            current_user: models.User = Depends(get_current_user)):
    result = verify_audit_chain(db)
    create_audit_entry(db, "AUDIT_CHAIN_VERIFIED", user=current_user.username)
    return result


# ─── Compliance ───────────────────────────────────────────────────────────────

@app.get("/compliance-report", tags=["Compliance"])
def compliance_report(db: Session = Depends(get_db)):
    from sqlalchemy import func
    total_files = db.query(models.File).filter(models.File.is_deleted == False).count()
    total_users = db.query(models.User).count()
    total_logs = db.query(models.AuditLog).count()
    deleted_files = db.query(models.File).filter(models.File.is_deleted == True).count()
    all_files = db.query(models.File).filter(models.File.is_deleted == False).all()
    total_refs = sum(f.reference_count or 1 for f in all_files)
    dedup_ratio = round((total_refs - total_files) / max(total_refs, 1) * 100, 1)
    region_counts = db.query(models.File.data_region, func.count(models.File.id)).filter(
        models.File.is_deleted == False
    ).group_by(models.File.data_region).all()
    return {
        "platform": "TrustVault v2.0",
        "encryption": "AES-256-GCM",
        "compliance_standards": ["GDPR", "ISO/IEC 27001", "Zero-Trust"],
        "stats": {
            "active_files": total_files, "gdpr_erased_files": deleted_files,
            "total_users": total_users, "total_audit_events": total_logs,
            "deduplication_savings_percent": dedup_ratio,
            "data_by_region": {r: c for r, c in region_counts},
        }
    }


# ─── Admin ────────────────────────────────────────────────────────────────────

@app.post("/admin/change-role", tags=["Admin"])
def change_user_role(req: schemas.ChangeRoleRequest, db: Session = Depends(get_db),
                     current_user: models.User = Depends(require_admin)):
    target = db.query(models.User).filter(models.User.username == req.username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if req.role not in ("admin", "user", "readonly"):
        raise HTTPException(status_code=400, detail="Role must be admin, user, or readonly")
    target.role = req.role
    db.commit()
    create_audit_entry(db, "ROLE_CHANGED", user=current_user.username,
                       meta_data=f"target={req.username},new_role={req.role}")
    return {"message": f"{req.username} role changed to {req.role}"}


@app.get("/admin/users", tags=["Admin"])
def list_users(db: Session = Depends(get_db),
               current_user: models.User = Depends(require_admin)):
    return [
        {"id": u.id, "username": u.username, "email": u.email,
         "role": u.role, "is_active": u.is_active, "data_region": u.data_region,
         "created_at": str(u.created_at)}
        for u in db.query(models.User).all()
    ]