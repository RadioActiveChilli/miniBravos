# miniBravos

A lightweight agentic security scanner that connects to the [CXG (CERT-X-GEN)](https://www.bugb.io/cert-x-gen) MCP server, reasons about what to scan, and executes vulnerability detection templates against a target — with a human-in-the-loop approval checkpoint before any scan runs.

Built as a proof-of-concept that mirrors the architecture of the [Bravos](https://www.bugb.io/bravos) security workbench on a smaller, more comprehensible scale.

---

## Architecture

```
main.py
  └──► src/agent.py  ──►  src/mcp_client.py  ──►  CXG MCP Server (stdio subprocess)
              │                                            │
              │                                            └──► 160 scan templates
              │
              ├──►  llama-cpp-python (local LLM)
              │         └──► Llama-3.2-1B-Instruct (GGUF, CPU inference)
              │
              └──►  src/reporter.py  ──►  reports/<timestamp>.html + .json
```

| File | Responsibility |
|---|---|
| `main.py` | Entry point — adds `src/` to path, starts the agent |
| `src/agent.py` | Agent loop — LLM reasoning, MCP tool calls, human-in-the-loop |
| `src/mcp_client.py` | Thin async wrapper around the MCP stdio client |
| `src/reporter.py` | Builds and saves HTML + JSON scan reports |
| `src/config.py` | All configuration constants and path resolution |

## Project Structure

```
miniBravos/
├── main.py              # entry point
├── src/
│   ├── agent.py         # agent loop
│   ├── config.py        # configuration and path resolution
│   ├── mcp_client.py    # MCP stdio client wrapper
│   └── reporter.py      # HTML + JSON report generation
├── tests/               # test suite
├── models/              # GGUF model files (gitignored)
├── reports/             # scan output (gitignored)
├── requirements.txt
└── .gitignore
```

1. **Agent connects** to the CXG MCP server as a stdio subprocess
2. **Discovers tools** available on the server
3. **Local LLM reasons** about which scan tool and arguments to use
4. **Human-in-the-loop checkpoint** — user approves or rejects before anything runs
5. **Scan executes** via MCP tool call
6. **Findings parsed** directly from CXG's structured JSON output
7. **Report saved** as both HTML and JSON to `reports/`

---

## Prerequisites

- Python 3.12+
- [CXG](https://github.com/Bugb-Technologies/cert-x-gen) installed and on PATH
- Docker (for test targets)
- ~2GB disk space for the LLM model

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
```

**3. Download the LLM model**
```bash
mkdir -p models
venv/bin/python3 -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='bartowski/Llama-3.2-1B-Instruct-GGUF', filename='Llama-3.2-1B-Instruct-Q4_K_M.gguf', local_dir='models/')"
```

**4. Install and update CXG templates**
```bash
curl -fsSL https://raw.githubusercontent.com/Bugb-Technologies/cert-x-gen/main/install.sh | bash
cxg template update
```

**5. Spin up a test target**

Redis (unauthenticated):
```bash
docker run -d -p 6379:6379 redis:6.0 --protected-mode no
```

Log4Shell:
```bash
docker run -d -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
```

---

## Configuration

Edit `src/config.py` before running:

```python
TARGET = "localhost:6379"   # host:port of your test target
SCOPE  = "network"          # "network" or "web"
VERBOSE_REASONING = True    # print LLM reasoning and raw scan output
```

---

## Running

```bash
venv/bin/python3 main.py
```

The agent will:
- Connect to CXG's MCP server
- Display available scan tools
- Ask the LLM to select the right approach
- **Pause and ask for your approval** before running anything
- Execute the scan if approved
- Save a report to `reports/report_<timestamp>.html` and `.json`

---

## Human-in-the-loop

Typing `n` at the checkpoint triggers a second suggestion from the agent. Typing `n` again aborts cleanly — nothing is scanned without consent.

```
╭─────────────── Checkpoint — Approve Scan? ───────────────╮
│ Tool: cxg_scan                                           │
│ Arguments: {"target": "localhost:6379", "scope": "network"} │
│ Reasoning: Redis network scan using unauthenticated ...  │
╰──────────────────────────────────────────────────────────╯
Proceed with scan? [y/n] (n):
```

---

## References

- [CERT-X-GEN platform](https://www.bugb.io/cert-x-gen)
- [Bravos system](https://www.bugb.io/bravos)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
