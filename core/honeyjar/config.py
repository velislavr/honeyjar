"""Runtime configuration, read from environment variables."""
import json
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://honeyjar:honeyjar@localhost:5432/honeyjar")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
RULES_DIR = Path(os.environ.get("RULES_DIR", _ROOT / "rules"))
GEOIP_DIR = Path(os.environ.get("GEOIP_DIR", _ROOT / "data" / "geoip"))
SCHEMA_FILE = Path(os.environ.get("SCHEMA_FILE", _ROOT / "db" / "schema.sql"))

# Sensor registry: {"sensor-id": {"token": "...", "label": "Frankfurt", "lat": 50.1, "lon": 8.7}}
SENSORS: dict[str, dict] = json.loads(os.environ.get("SENSORS", "{}"))
TOKEN_TO_SENSOR = {v["token"]: k for k, v in SENSORS.items() if v.get("token")}

# Optional threat-intel API keys; lookups are skipped when unset.
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
MALWAREBAZAAR_KEY = os.environ.get("MALWAREBAZAAR_KEY", "")

# Session triage: rules-only verdicts unless the Jev decision model (TypeSafe AI) is enabled.
TRIAGE_ENABLED = os.environ.get("TRIAGE_ENABLED", "1") == "1"
JEV_API_URL = os.environ.get("JEV_API_URL", "https://api.typesafe.ai/v1/systemone")
JEV_API_KEY = os.environ.get("JEV_API_KEY", "")
JEV_MODEL = os.environ.get("JEV_MODEL", "jev-1.13.0")
JEV_DAILY_TOKEN_BUDGET = int(os.environ.get("JEV_DAILY_TOKEN_BUDGET", "2000000"))
# Keyless endpoints (e.g. OpenCode's free jev-1.13-free proxy) need JEV_ENABLED=1 without a key.
JEV_ENABLED = os.environ.get("JEV_ENABLED", "1" if JEV_API_KEY else "0") == "1"
JEV_MIN_INTERVAL = float(os.environ.get("JEV_MIN_INTERVAL", "0"))

CORS_ORIGINS = [o for o in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",") if o]
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "240"))

RAW_STREAM = "events:raw"
LIVE_CHANNEL = "events:live"
