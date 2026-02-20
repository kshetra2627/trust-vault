from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:Kshetra%402627@localhost:5433/trustvault"
)

engine = create_engine(
    DATABASE_URL,
    # Connection pooling for reliability under load
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,     # test connections before use (handles dropped DB connections)
    pool_recycle=3600,      # recycle connections every hour (prevents stale connections)
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency — yields a DB session and always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()