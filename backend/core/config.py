import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')

OSINT_DB_FILE = os.path.join(DATA_DIR, 'osint.db')
VT_API_KEYS_FILE = os.path.join(DATA_DIR, 'api_keys.txt')

# Create data dir if not exists
os.makedirs(DATA_DIR, exist_ok=True)
