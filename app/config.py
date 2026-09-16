import os
import secrets

# Server & Network Configuration
PORT = int(os.getenv("PORT", "8080"))
HOST = os.getenv("HOST", "0.0.0.0")

# Security & Credentials
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "milijon_admin")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(16))

# Domain & Paths
SERVER_DOMAIN = os.getenv("SERVER_DOMAIN", "")  # Auto-detected from Host header if empty
WS_PATH_VLESS = os.getenv("WS_PATH_VLESS", "/milijon-vl")
WS_PATH_TROJAN = os.getenv("WS_PATH_TROJAN", "/milijon-tr")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "milijon.db"))

# Default CDN / Clean IPs for Circumvention Presets
PRESET_CLEAN_IPS = {
    "iran": [
        "104.16.132.229",
        "104.16.133.229",
        "172.67.181.18",
        "104.17.147.22",
        "162.159.140.97",
        "141.101.90.10"
    ],
    "china": [
        "104.18.2.161",
        "104.19.18.151",
        "172.64.80.1",
        "198.41.214.162"
    ],
    "russia": [
        "104.21.35.12",
        "172.67.143.205",
        "188.114.96.3",
        "188.114.97.3"
    ]
}

# Regional Fragmentation Presets for bypassing DPI
PRESET_FRAGMENT = {
    "iran": {"length": "100-200", "interval": "10-20", "packets": "tlshello"},
    "china": {"length": "50-100", "interval": "5-15", "packets": "1-3"},
    "russia": {"length": "100-300", "interval": "10-30", "packets": "tlshello"}
}
