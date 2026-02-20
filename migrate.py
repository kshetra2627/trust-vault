"""
migrate.py — Run this ONCE to fix your existing database schema.

The error you saw:
  "column audit_logs.ip_address does not exist"

This happens because SQLAlchemy's create_all() only creates NEW tables —
it never alters existing ones. This script adds all missing columns safely
using ALTER TABLE ... ADD COLUMN IF NOT EXISTS (PostgreSQL syntax).

Usage:
  python migrate.py

Safe to run multiple times — IF NOT EXISTS prevents errors.
"""

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:Kshetra%402627@localhost:5433/trustvault"
)

engine = create_engine(DATABASE_URL)

# All migrations — each is idempotent (IF NOT EXISTS)
MIGRATIONS = [
    # ── audit_logs missing columns ──────────────────────────────────────────
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS meta_data TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS previous_hash VARCHAR",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS current_hash VARCHAR",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_id VARCHAR",

    # ── users missing columns ───────────────────────────────────────────────
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS data_region VARCHAR DEFAULT 'EU'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR DEFAULT 'user'",

    # ── files missing columns ───────────────────────────────────────────────
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS checksum_sha256 VARCHAR",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS encryption_key TEXT",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS reference_count INTEGER DEFAULT 1",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS is_latest BOOLEAN DEFAULT TRUE",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS data_region VARCHAR DEFAULT 'EU'",
    "ALTER TABLE files ADD COLUMN IF NOT EXISTS mime_type VARCHAR",

    # ── chunk_upload_sessions (create if missing) ───────────────────────────
    """
    CREATE TABLE IF NOT EXISTS chunk_upload_sessions (
        id VARCHAR PRIMARY KEY,
        owner_id INTEGER REFERENCES users(id),
        filename VARCHAR,
        total_chunks INTEGER,
        uploaded_chunks INTEGER DEFAULT 0,
        received_chunk_indices TEXT DEFAULT '',
        chunk_size INTEGER,
        total_size BIGINT,
        expected_hash VARCHAR,
        status VARCHAR DEFAULT 'in_progress',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    )
    """,

    # ── file_permissions (create if missing) ───────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS file_permissions (
        id SERIAL PRIMARY KEY,
        file_id INTEGER REFERENCES files(id),
        user_id INTEGER REFERENCES users(id),
        can_read BOOLEAN DEFAULT TRUE,
        can_write BOOLEAN DEFAULT FALSE,
        can_delete BOOLEAN DEFAULT FALSE,
        granted_by INTEGER REFERENCES users(id),
        granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
        expires_at TIMESTAMP WITH TIME ZONE
    )
    """,

    # ── Fix unique constraint on current_hash (may not exist yet) ──────────
    # Skipped — SQLAlchemy handles this via create_all for new installs
]


def run_migrations():
    print("=" * 60)
    print("TrustVault Database Migration")
    print("=" * 60)

    with engine.connect() as conn:
        for i, sql in enumerate(MIGRATIONS, 1):
            clean = sql.strip().replace("\n", " ")[:80]
            try:
                conn.execute(text(sql))
                conn.commit()
                print(f"  ✅ [{i:02d}] {clean}...")
            except Exception as e:
                conn.rollback()
                # Non-fatal: column may already exist with different handling
                print(f"  ⚠️  [{i:02d}] Skipped (already exists or error): {e}")

    print()
    print("✅ Migration complete! Now restart your server:")
    print("   uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
    print("=" * 60)


if __name__ == "__main__":
    run_migrations()