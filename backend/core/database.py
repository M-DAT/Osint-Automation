import sqlite3
import json
import bcrypt
from core.config import OSINT_DB_FILE

def init_osint_db():
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
                    service_name TEXT PRIMARY KEY,
                    api_key TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT,
                    status TEXT DEFAULT 'active'
                )''')
    conn.commit()
    conn.close()

def get_osint_keys():
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("SELECT service_name, api_key FROM api_keys")
    keys = {}
    for row in c.fetchall():
        try:
            parsed = json.loads(row[1])
            if isinstance(parsed, list):
                keys[row[0]] = parsed
            else:
                keys[row[0]] = [row[1]] if row[1] else []
        except:
            keys[row[0]] = [row[1]] if row[1] else []
    conn.close()
    return keys

def add_osint_key(service, key):
    if not key or not key.strip():
        return
    keys_dict = get_osint_keys()
    existing = keys_dict.get(service, [])
    if key not in existing:
        existing.append(key)
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO api_keys (service_name, api_key) VALUES (?, ?)", (service, json.dumps(existing)))
    conn.commit()
    conn.close()

def create_user(username, password, role='user'):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, 'active')", (username, password_hash, role))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def get_user_by_username(username):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "password_hash": row[2], "role": row[3], "status": row[4]}
    return None

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def get_all_users():
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, role, status FROM users")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1], "role": r[2], "status": r[3]} for r in rows]

def get_user_by_id(user_id):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role, status FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "password_hash": row[2], "role": row[3], "status": row[4]}
    return None

def update_user_password(user_id, new_password):
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_user_role(user_id, role):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()

def update_user_status(user_id, status):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
    conn.commit()
    conn.close()

def update_username(user_id, new_username):
    conn = sqlite3.connect(OSINT_DB_FILE)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success
