import os
from pathlib import Path

# Load .env from project root if present (no third-party library needed)
_env_file = Path(__file__).parent.parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

TARGET = "http://localhost:8080"
SCOPE = "web"

TARGET_URL = "http://localhost:8080"
TARGET_TYPE = "web"  # "web" or "network"

# Credentials used by recon to log in before crawling.
# Set TARGET_LOGIN_URL to "" to skip the login step entirely.
TARGET_LOGIN_URL      = "http://localhost:8080/login.php"
TARGET_USERNAME       = "admin"
TARGET_PASSWORD       = "password"

# Optional post-login security level page (DVWA-specific).
# Set to "" to skip. "low" makes all DVWA vulnerabilities exploitable.
TARGET_SECURITY_URL   = "http://localhost:8080/security.php"
TARGET_SECURITY_LEVEL = "low"

# URL path fragments that recon uses to flag likely vulnerability surfaces.
# Phase 3 triggers on these even if CXG returns no high/critical findings.
VULN_PATH_HINTS = ["/vulnerabilities/", "/sqli", "/xss", "/upload", "/exec", "/fi/"]

VERBOSE_REASONING = True

_ROOT = Path(__file__).parent.parent

MODEL_PATH = str(Path.home() / ".local" / "share" / "models" / "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf")
MODEL_NAME = Path(MODEL_PATH).name
MODEL_CONTEXT = 4096

CXG_COMMAND = "/usr/local/bin/cxg"
CXG_ARGS = ["mcp"]

REPORTS_DIR = str(_ROOT / "reports")

RECON_MAX_DEPTH = 2
RECON_TIMEOUT = 15000  # ms per page.goto call
