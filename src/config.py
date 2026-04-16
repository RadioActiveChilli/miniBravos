from pathlib import Path

TARGET = "localhost:6379"
SCOPE = "network"
VERBOSE_REASONING = True

_ROOT = Path(__file__).parent.parent

MODEL_PATH = str(_ROOT / "models" / "Llama-3.2-1B-Instruct-Q4_K_M.gguf")
MODEL_CONTEXT = 4096

CXG_COMMAND = "/usr/local/bin/cxg"
CXG_ARGS = ["mcp"]

REPORTS_DIR = str(_ROOT / "reports")
