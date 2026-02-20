import hashlib
import uuid
import time
from sqlalchemy.orm import Session
import models


def create_audit_entry(
    db: Session,
    action: str,
    user: str = "system",
    file_hash: str = None,
    meta_data: str = None,
    ip_address: str = None,
):
    # Read last hash from DB — no in-memory global (which resets on restart)
    last_log = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
    previous_hash = last_log.current_hash if last_log else "0" * 64

    entry_id = str(uuid.uuid4())[:8]
    record = f"{time.time()}|{user}|{action}|{file_hash or ''}|{ip_address or ''}|{previous_hash}"
    current_hash = hashlib.sha256(record.encode()).hexdigest()

    log = models.AuditLog(
        entry_id=entry_id,
        user=user,
        action=action,
        file_hash=file_hash,
        meta_data=meta_data,
        ip_address=ip_address,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(log)
    db.commit()
    return current_hash


def verify_audit_chain(db: Session) -> dict:
    logs = db.query(models.AuditLog).order_by(models.AuditLog.id.asc()).all()
    if not logs:
        return {"valid": True, "entries_checked": 0, "message": "No logs to verify"}

    prev = "0" * 64
    for log in logs:
        if log.previous_hash != prev:
            return {
                "valid": False,
                "entries_checked": len(logs),
                "broken_at_entry_id": log.id,
                "message": "⚠️ CHAIN INTEGRITY VIOLATION DETECTED"
            }
        prev = log.current_hash

    return {
        "valid": True,
        "entries_checked": len(logs),
        "message": "✅ Audit chain integrity verified — all entries are tamper-proof"
    }