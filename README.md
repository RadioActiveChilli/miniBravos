# miniBravos

A lightweight agentic security scanner that connects to the [CXG (CERT-X-GEN)](https://www.bugb.io/cert-x-gen) MCP server, reasons about what to scan, and executes vulnerability detection templates against a target — with a human-in-the-loop approval checkpoint before any scan or exploit attempt runs.

Built as a proof-of-concept that mirrors the architecture of the [Bravos](https://www.bugb.io/bravos) security workbench on a smaller, more comprehensible scale.

---

## Architecture

The pipeline runs in three phases:

```
Phase 1 — Recon (Playwright)
        ↓
Phase 2 — Detection (LLM → CXG via MCP)
        ↓
Phase 3 — Validation (Playwright, LLM-directed)
```

```
main.py
  └──► src/agent.py ──► src/recon.py       (Playwright BFS crawler, login, session)
            │
            ├──► src/mcp_client.py ──► CXG MCP Server (stdio subprocess)
            │                               └──► 160 scan templates
            │
            ├──► llama-cpp-python (local LLM, no API key)
            │         └──► Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
            │
            ├──► src/verifier.py    (Playwright exploit verification layer)
            │
            └──► src/reporter.py ──► reports/<timestamp>.html + .json
```

| File | Responsibility |
|---|---|
| `main.py` | Entry point — adds `src/` to path, starts the agent |
| `src/agent.py` | Agent loop — recon, LLM reasoning, MCP tool calls, validation, token tracking |
| `src/recon.py` | Playwright BFS crawler — login, security level, endpoint/form/header collection |
| `src/verifier.py` | Constrained Playwright verification layer — predefined exploit scripts per vuln type |
| `src/mcp_client.py` | Thin async wrapper around the MCP stdio client |
| `src/reporter.py` | Builds and saves HTML + JSON scan reports |
| `src/config.py` | All configuration constants and path resolution |

## Project Structure

```
miniBravos/
├── main.py              # entry point
├── src/
│   ├── agent.py         # agent loop (all three phases)
│   ├── config.py        # configuration and path resolution
│   ├── mcp_client.py    # MCP stdio client wrapper
│   ├── recon.py         # Playwright recon crawler
│   ├── verifier.py      # Playwright verification layer
│   └── reporter.py      # HTML + JSON report generation
├── tests/               # test suite
├── reports/             # scan output (gitignored)
├── requirements.txt
└── .gitignore
```

---

## How It Works

**Phase 1 — Recon**
- Playwright (headless Chromium) logs into the target, sets DVWA security to Low, then BFS-crawls up to `RECON_MAX_DEPTH`
- Collects endpoints, forms, response headers, session cookies, and XHR/fetch calls
- Session cookies are passed to Phase 2 (CXG) and held open for Phase 3

**Phase 2 — Detection**
- Local LLM reads the recon summary and selects the most appropriate CXG scan template
- Human-in-the-loop checkpoint — approve, reject (triggers alt suggestion), or abort
- CXG executes the template; findings parsed from structured JSON output

**Phase 3 — Validation**
- LLM maps recon-discovered vulnerability endpoints to predefined verification actions
- Per-action human checkpoint before any payload is sent
- Playwright executes the verification script; result is CONFIRMED EXPLOITABLE, NOT REPRODUCED, or PENDING
- Session expiry is detected and recovered automatically before verification begins

**Reports**
- JSON and HTML saved to `reports/` after every run
- HTML includes collapsible recon details, LLM context, findings, validation results with status badges, agent interpretation, and token usage
- Token usage (prompt / completion / total) tracked across all LLM calls and shown in the terminal

---

## Verification Actions

| Action | What it does |
|---|---|
| `verify_reflected_xss` | Detects field name from form, injects `<script>alert(1)</script>` via query param; falls back to `<img src="xss_canary">` if script tags are filtered |
| `verify_stored_xss` | Fills all inputs and textareas with a canary string, submits, revisits the page to confirm storage and reflection |
| `verify_sql_injection` | Navigates to `?id='&Submit=Submit`; checks response for SQL error messages from the database |
| `verify_auth_bypass` | Submits SQLi/bypass payload as username; checks post-login indicators in response |
| `verify_log_injection` | Injects payload via User-Agent and X-Forwarded-For headers; looks for 5xx server errors |

The LLM picks actions by name; Playwright runs a predetermined script. No freestyle LLM-to-browser instructions.

---

## Prerequisites

- Python 3.12+
- [CXG](https://github.com/Bugb-Technologies/cert-x-gen) installed and on PATH
- Docker (for test targets)
- ~5GB disk space for the LLM model
- Playwright Chromium binary (`playwright install chromium`)

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/RadioActiveChilli/miniBravos.git
cd miniBravos
```

**2. Create a virtual environment and install dependencies**
```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/playwright install chromium
```

**3. Download the LLM model**
```bash
mkdir -p ~/.local/share/models
# Recommended: Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf (~4.6GB)
venv/bin/python3 -c "
from huggingface_hub import hf_hub_download
hf_hub_download(
    repo_id='bartowski/Meta-Llama-3.1-8B-Instruct-GGUF',
    filename='Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf',
    local_dir='~/.local/share/models/'
)"
```

Models are stored globally at `~/.local/share/models/` so they can be shared across projects. Update `MODEL_NAME` in `src/config.py` to match the filename you download.

**4. Install and update CXG templates**
```bash
curl -fsSL https://raw.githubusercontent.com/Bugb-Technologies/cert-x-gen/main/install.sh | bash
cxg template update
```

**5. Spin up DVWA (recommended test target)**
```bash
docker network create dvwa-net 2>/dev/null || true

docker run -d -p 127.0.0.1:3306:3306 \
  --name dvwa-mysql --network dvwa-net \
  -e MYSQL_ROOT_PASSWORD=rootpassword \
  -e MYSQL_DATABASE=dvwa \
  -e MYSQL_USER=dvwa \
  -e MYSQL_PASSWORD='p@ssw0rd' \
  mariadb:10.6

# Wait ~10s for MariaDB to initialise, then:
docker run -d -p 127.0.0.1:8080:80 \
  --network dvwa-net \
  -e DB_SERVER=dvwa-mysql \
  -e DB_USERNAME=dvwa \
  -e DB_PASSWORD='p@ssw0rd' \
  ghcr.io/digininja/dvwa
```

Visit `http://localhost:8080/setup.php` and click **Create / Reset Database**, then confirm login at `http://localhost:8080` with `admin` / `password`.

---

## Configuration

Edit `src/config.py` before running:

```python
TARGET      = "localhost:8080"         # host:port for CXG
SCOPE       = "web"                    # "network" or "web"
TARGET_URL  = "http://localhost:8080"  # full URL for Playwright
TARGET_TYPE = "web"                    # "web" enables Phase 1 and Phase 3

TARGET_LOGIN_URL   = "http://localhost:8080/login.php"
TARGET_USERNAME    = "admin"
TARGET_PASSWORD    = "password"
TARGET_SECURITY_URL   = "http://localhost:8080/security.php"
TARGET_SECURITY_LEVEL = "low"

MODEL_NAME = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
VERBOSE_REASONING = True
```

For **headless / headed Playwright**: open `src/recon.py` and change `headless=True` to `headless=False` to watch the browser navigate live.

---

## Running

```bash
venv/bin/python3 main.py
```

The agent will run all three phases and pause for your approval before each scan and each verification action. A token usage summary and report paths are printed at the end.

---

## Human-in-the-loop

Every scan and every exploit verification requires explicit approval:

**Phase 2 checkpoint:**
```
╭─────────────── Checkpoint — Approve Scan? ───────────────╮
│ Tool: cxg_template_test                                   │
│ Arguments: {"target": "http://localhost:8080", ...}       │
│ Reasoning: ...                                            │
╰───────────────────────────────────────────────────────────╯
Proceed with scan? [y/n] (n):
```
- `y` — run the scan
- `n` — reject; agent proposes an alternative and presents a second checkpoint
- `n` again — abort cleanly

**Phase 3 checkpoint (per action):**
```
╭──────── Checkpoint — Approve Verification? ────────╮
│ Action:   verify_reflected_xss                      │
│ Endpoint: http://localhost:8080/vulnerabilities/... │
│ Payload:  <script>alert(1)</script>                 │
╰─────────────────────────────────────────────────────╯
Run verification? [y/n] (n):
```
- `y` — execute the Playwright verification script
- `n` — skip; result recorded as PENDING in the report

---

## Tests

```bash
venv/bin/python -m pytest tests/ -q
```

All external dependencies (Playwright, CXG, LLM) are mocked. Tests cover happy path, rejection flow, abort, JSON parser edge cases, recon schema, verifier functions, and validation approval/rejection.

> **Note:** The test suite is not fully up to date. `tests/test_verifier.py` does not yet cover `verify_stored_xss` and the page mock needs updating for the Playwright locator API. This is pending and does not affect runtime behaviour.

---

## References

- [CERT-X-GEN platform](https://www.bugb.io/cert-x-gen)
- [Bravos system](https://www.bugb.io/bravos)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
