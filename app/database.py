import os
import sqlite3
import datetime
import uuid
import hashlib
from typing import List, Optional, Dict, Any
from app.config import DB_PATH

# Determine active database path dynamically
ACTIVE_DB_PATH = DB_PATH

def get_db():
    global ACTIVE_DB_PATH
    try:
        conn = sqlite3.connect(ACTIVE_DB_PATH, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = DELETE;")
        return conn
    except Exception:
        ACTIVE_DB_PATH = os.path.join("/tmp", "milijon.db")
        conn = sqlite3.connect(ACTIVE_DB_PATH, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = DELETE;")
        return conn

def init_db():
    global ACTIVE_DB_PATH
    for path_candidate in [ACTIVE_DB_PATH, os.path.join("/tmp", "milijon.db")]:
        try:
            conn = sqlite3.connect(path_candidate, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    uuid TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    upload_bytes INTEGER DEFAULT 0,
                    download_bytes INTEGER DEFAULT 0,
                    country_preset TEXT DEFAULT 'iran',
                    notes TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()

            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                default_uuid = str(uuid.uuid4())
                default_pass = "milijon_user"
                p_hash = hashlib.sha224(default_pass.encode('utf-8')).hexdigest()
                now_iso = datetime.datetime.utcnow().isoformat()
                cursor.execute("""
                    INSERT INTO users (username, uuid, password, password_hash, created_at, is_active, country_preset, notes)
                    VALUES (?, ?, ?, ?, ?, 1, 'iran', 'Default VIP User')
                """, ("DefaultUser", default_uuid, default_pass, p_hash, now_iso))
                conn.commit()
            
            ACTIVE_DB_PATH = path_candidate
            conn.close()
            return
        except Exception as e:
            continue

init_db()

def get_all_users() -> List[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_user_by_uuid(user_uuid: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE uuid = ? AND is_active = 1", (user_uuid.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_password_hash(p_hash: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE password_hash = ? AND is_active = 1", (p_hash.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def create_user(username: str, user_uuid: Optional[str] = None, password: Optional[str] = None,
                expires_at: Optional[str] = None, country_preset: str = 'iran', notes: str = '') -> Dict[str, Any]:
    if not user_uuid:
        user_uuid = str(uuid.uuid4())
    else:
        user_uuid = user_uuid.strip().lower()

    if not password:
        password = str(uuid.uuid4())[:12]
    
    p_hash = hashlib.sha224(password.encode('utf-8')).hexdigest()
    created_at = datetime.datetime.utcnow().isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, uuid, password, password_hash, created_at, expires_at, is_active, country_preset, notes)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (username.strip(), user_uuid, password, p_hash, created_at, expires_at, country_preset, notes))
        conn.commit()
        user_id = cursor.lastrowid
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return dict(cursor.fetchone())

def delete_user(user_id: int) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0

def toggle_user_status(user_id: int) -> Optional[int]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        new_status = 0 if row["is_active"] == 1 else 1
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        return new_status

def add_traffic(user_id: int, up: int, down: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?
            WHERE id = ?
        """, (up, down, user_id))
        conn.commit()
