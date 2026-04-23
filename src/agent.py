import ast
import asyncio
import json
import re
from datetime import datetime

from llama_cpp import Llama
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule

from config import (
    TARGET, SCOPE, VERBOSE_REASONING,
    MODEL_PATH, MODEL_CONTEXT,
)
from mcp_client import MCPClient
from reporter import save_report

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
        reasoning = selection.get("reasoning", "")
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
                "content": (
                    "You are a security scanning agent. The user rejected your proposed scan. "
                    "Reply with ONLY a valid JSON object using double quotes. No explanation. No markdown. "
                    "Format: {\"tool_name\": \"<name>\", \"arguments\": {\"target\": \"<host:port>\", \"scope\": \"<scope>\"}, \"reasoning\": \"<one sentence>\"}"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Target: {TARGET}\nScope: {SCOPE}\n\n"
                    f"The user rejected the scan using tool '{tool_name}'. "
                    f"Available scan tools:\n{scan_tools_summary}\n\n"
                    "Suggest a less intrusive alternative. Reply with JSON only. Use the target and scope values exactly as given."
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
