import ast
import asyncio
import json
import os
from datetime import datetime

from llama_cpp import Llama
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule

from config import (
    TARGET, SCOPE, VERBOSE_REASONING,
    MODEL_PATH, MODEL_CONTEXT,
    REPORTS_DIR,
)
from mcp_client import MCPClient

console = Console()


_llm = None

def get_llm() -> Llama:
    global _llm
    if _llm is None:
        _llm = Llama(model_path=MODEL_PATH, n_ctx=MODEL_CONTEXT, verbose=False)
    return _llm

async def llm(messages: list[dict]) -> str:
    def _call():
        model = get_llm()
        response = model.create_chat_completion(messages=messages)
        return response["choices"][0]["message"]["content"]
    return await asyncio.to_thread(_call)


def parse_llm_json(raw: str) -> dict:
    """Parse LLM output that may use single quotes, markdown fences, or unclosed braces."""
    clean = raw.strip().strip("```json").strip("```").strip()
    # Try as-is first
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass
    # Try closing unclosed braces/brackets
    for closing in ["}", "}}", "]}}", "}]}"]:
        try:
            return json.loads(clean + closing)
        except json.JSONDecodeError:
            pass
    # Try as a Python literal (handles single quotes)
    return ast.literal_eval(clean)


def save_report(data: dict) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    html_path = os.path.join(REPORTS_DIR, f"report_{ts}.html")
    findings_html = ""
    for finding in data.get("findings", []):
        findings_html += f"""
        <div class="finding">
            <h3>{finding.get('title', 'Finding')}</h3>
            <p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
            <p><strong>Description:</strong> {finding.get('description', '')}</p>
            <p><strong>Evidence:</strong> {finding.get('evidence', '')}</p>
            <p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>
        </div>"""

    with open(html_path, "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>miniBravos Report — {ts}</title>
  <style>
    body {{ font-family: sans-serif; max-width: 860px; margin: 40px auto; padding: 0 20px; background: #f9f9f9; }}
    h1 {{ color: #c0392b; }}
    .meta {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-bottom: 24px; }}
    .finding {{ background: #fff; border-left: 4px solid #c0392b; padding: 16px; margin-bottom: 16px; border-radius: 4px; }}
    .finding h3 {{ margin-top: 0; }}
    .summary {{ background: #fff; border: 1px solid #ddd; padding: 16px; border-radius: 6px; margin-top: 24px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>miniBravos Scan Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {data['target']}</p>
    <p><strong>Scope:</strong> {data['scope']}</p>
    <p><strong>Template:</strong> {data['template_used']}</p>
    <p><strong>Timestamp:</strong> {data['timestamp']}</p>
  </div>
  <h2>Findings</h2>
  {findings_html if findings_html else '<p>No findings extracted.</p>'}
  <h2>Agent Interpretation</h2>
  <div class="summary">{data.get('interpretation', '')}</div>
</body>
</html>""")

    return json_path, html_path


async def run():
    console.print(Rule("[bold red]miniBravos Agent[/bold red]"))
    console.print(f"[bold]Target:[/bold] {TARGET}   [bold]Scope:[/bold] {SCOPE}\n")

    # --- Connect to CXG MCP server ---
    console.print("[cyan]Connecting to CXG MCP server...[/cyan]")
    try:
        async with MCPClient() as client:
            console.print("[green]Connected.[/green]\n")
            await _agent_loop(client)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


async def _agent_loop(client: MCPClient):

    # --- Discover available tools ---
    tools = await client.list_tools()
    tools_summary = "\n".join(
        f"- {t.name}: {t.description}" for t in tools
    )

    if VERBOSE_REASONING:
        console.print(Panel(tools_summary, title="[bold]CXG Tools Discovered[/bold]", border_style="blue"))

    # Only expose scan-execution tools to the LLM — exclude utility/management tools
    SCAN_TOOLS = {"cxg_scan", "cxg_template_test"}
    scan_tools_summary = "\n".join(
        f"- {t.name}: {t.description}" for t in tools if t.name in SCAN_TOOLS
    )

    # --- Ask LLM to pick the right tool/template ---
    console.print("[cyan]Asking model to select the best approach...[/cyan]\n")
    selection_prompt = [
        {
            "role": "system",
            "content": (
                "You are a security scanning agent. You must pick one of the listed tools to scan the target. "
                "Reply with ONLY a valid JSON object using double quotes. No explanation. No markdown. "
                "Format: {\"tool_name\": \"<name>\", \"arguments\": {\"target\": \"<host:port>\", \"scope\": \"<scope>\"}, \"reasoning\": \"<one sentence>\"}"
            ),
        },
        {
            "role": "user",
            "content": (
                f"Target: {TARGET}\nScope: {SCOPE}\n\n"
                f"Available scan tools:\n{scan_tools_summary}\n\n"
                "Reply with JSON only. Use the target and scope values exactly as given."
            ),
        },
    ]

    raw_selection = await llm(selection_prompt)

    if VERBOSE_REASONING:
        console.print(Panel(raw_selection, title="[bold]LLM Reasoning[/bold]", border_style="yellow"))

    try:
        selection = parse_llm_json(raw_selection)
        tool_name = selection["tool_name"]
        arguments = {k: v for k, v in selection["arguments"].items() if k != "reasoning"}
        reasoning = selection.get("reasoning") or arguments.pop("reasoning", "")
    except (json.JSONDecodeError, ValueError, KeyError, SyntaxError) as e:
        console.print(f"[red]Could not parse LLM response: {e}[/red]")
        console.print("[yellow]Raw response:[/yellow]", raw_selection)
        return

    # --- Human-in-the-loop checkpoint ---
    console.print(Panel(
        f"[bold]Tool:[/bold] {tool_name}\n"
        f"[bold]Arguments:[/bold] {json.dumps(arguments, indent=2)}\n"
        f"[bold]Reasoning:[/bold] {reasoning}",
        title="[bold yellow]Checkpoint — Approve Scan?[/bold yellow]",
        border_style="yellow",
    ))

    approval = Prompt.ask("Proceed with scan?", choices=["y", "n"], default="n")

    if approval == "n":
        console.print("[yellow]Scan rejected. Asking agent to suggest an alternative...[/yellow]\n")
        alt_prompt = [
            {
                "role": "system",
                "content": "You are a security scanning agent. The user rejected your proposed scan.",
            },
            {
                "role": "user",
                "content": (
                    f"The user rejected the scan using tool '{tool_name}' with args {arguments}. "
                    f"Available tools:\n{tools_summary}\n\n"
                    "Suggest a less intrusive alternative approach. Respond in JSON with keys: "
                    "'tool_name', 'arguments', 'reasoning'."
                ),
            },
        ]
        alt_raw = await llm(alt_prompt)
        if VERBOSE_REASONING:
            console.print(Panel(alt_raw, title="[bold]Alternative Suggestion[/bold]", border_style="magenta"))

        approval2 = Prompt.ask("Proceed with alternative scan?", choices=["y", "n"], default="n")
        if approval2 == "n":
            console.print("[red]Scan aborted by user.[/red]")
            return
        try:
            alt = parse_llm_json(alt_raw)
            tool_name = alt["tool_name"]
            arguments = alt["arguments"]
        except (json.JSONDecodeError, ValueError, KeyError, SyntaxError):
            console.print("[red]Could not parse alternative suggestion. Aborting.[/red]")
            return

    # --- Run the scan ---
    console.print(f"\n[cyan]Running scan with [bold]{tool_name}[/bold]...[/cyan]\n")
    try:
        result = await client.call_tool(tool_name, arguments)
        raw_output = str(result)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        return

    if VERBOSE_REASONING:
        console.print(Panel(raw_output[:2000], title="[bold]Raw Scan Output[/bold]", border_style="green"))

    # --- Parse findings directly from CXG JSON output ---
    findings = []
    scan_json = None
    try:
        # The result content is a string repr of an MCP CallToolResult object.
        # Extract the JSON text embedded in the text field.
        import re
        match = re.search(r"text='(\{.*\})'", raw_output, re.DOTALL)
        if match:
            text_content = match.group(1).encode().decode("unicode_escape")
            scan_json = json.loads(text_content)
        else:
            # Fallback: try parsing the whole thing
            scan_json = json.loads(raw_output)
    except Exception:
        pass

    if scan_json and "findings" in scan_json:
        for f in scan_json["findings"]:
            findings.append({
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "description": f.get("description", ""),
                "evidence": ", ".join(f.get("evidence_patterns", [])),
                "remediation": f.get("remediation") or "",
            })

    # --- LLM generates a plain-text summary ---
    console.print("[cyan]Generating summary...[/cyan]\n")
    summary_count = len(findings)
    high = sum(1 for f in findings if f["severity"] in ("high", "critical"))
    summary_prompt = [
        {
            "role": "system",
            "content": "You are a security analyst. Write a concise 2-3 sentence plain-text summary of a scan result. No JSON, no markdown.",
        },
        {
            "role": "user",
            "content": (
                f"Target: {TARGET}, Scope: {SCOPE}, Template: {tool_name}. "
                f"Total findings: {summary_count}, high/critical: {high}. "
                f"Finding titles: {[f['title'] for f in findings[:5]]}"
            ),
        },
    ]
    interpretation = await llm(summary_prompt)

    # --- Save report ---
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "target": TARGET,
        "scope": SCOPE,
        "template_used": tool_name,
        "findings": findings,
        "interpretation": interpretation,
        "raw_output": raw_output,
    }

    json_path, html_path = save_report(report_data)

    console.print(Panel(
        f"[green]JSON:[/green] {json_path}\n[green]HTML:[/green] {html_path}",
        title="[bold green]Report Saved[/bold green]",
        border_style="green",
    ))

if __name__ == "__main__":
    asyncio.run(run())
