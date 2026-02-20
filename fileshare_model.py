from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, LargeBinary

class FileShare(Base):
    __tablename__ = "file_shares"

    token = Column(String, primary_key=True, index=True)
    file_hash = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    sender_username = Column(String, nullable=False)
    recipient_username = Column(String, nullable=False)
    share_encrypted_data = Column(LargeBinary, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)