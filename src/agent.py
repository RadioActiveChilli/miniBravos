import ast
import asyncio
import json
import re
from dataclasses import asdict
from datetime import datetime

from llama_cpp import Llama
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule

from config import (
    TARGET, SCOPE, VERBOSE_REASONING,
    MODEL_PATH, MODEL_NAME, MODEL_CONTEXT,
    TARGET_URL, TARGET_TYPE,
    TARGET_LOGIN_URL, VULN_PATH_HINTS,
)
from mcp_client import MCPClient
from recon import run_recon, ensure_session
from reporter import save_report
from verifier import VERIFICATION_REGISTRY, VerificationAction

console = Console()


_llm = None
_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

def get_llm() -> Llama:
    global _llm
    if _llm is None:
        _llm = Llama(model_path=MODEL_PATH, n_ctx=MODEL_CONTEXT, verbose=False)
    return _llm

async def llm(messages: list[dict]) -> str:
    def _call():
        model = get_llm()
        response = model.create_chat_completion(messages=messages)
        usage = response.get("usage", {})
        _token_usage["prompt_tokens"]     += usage.get("prompt_tokens", 0)
        _token_usage["completion_tokens"] += usage.get("completion_tokens", 0)
        _token_usage["total_tokens"]      += usage.get("total_tokens", 0)
        return response["choices"][0]["message"]["content"]
    return await asyncio.to_thread(_call)


def parse_llm_json(raw: str):
    """Parse LLM output that may use single quotes, markdown fences, or unclosed braces."""
    clean = raw.strip().strip("```json").strip("```").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass
    for closing in ["}", "}}", "]}}", "}]}"]:
        try:
            return json.loads(clean + closing)
        except json.JSONDecodeError:
            pass
    return ast.literal_eval(clean)


def _recon_summary(recon_data: dict) -> str:
    """Condensed one-paragraph summary of recon data for the LLM selection prompt."""
    ep_count = len(recon_data.get("endpoints", []))
    form_count = len(recon_data.get("forms", []))
    top_eps = recon_data.get("endpoints", [])[:5]
    headers_sample = {}
    for url, hdrs in list(recon_data.get("headers", {}).items())[:2]:
        headers_sample[url] = {
            k: v for k, v in hdrs.items()
            if k.lower() in ("server", "x-powered-by", "content-type", "set-cookie")
        }
    xhr_count = len(recon_data.get("client_behaviour", []))
    return (
        f"Recon found {ep_count} endpoints, {form_count} forms, "
        f"{xhr_count} XHR/fetch calls. "
        f"Top endpoints: {top_eps}. "
        f"Notable headers: {json.dumps(headers_sample)}."
    )


async def run():
    console.print(Rule("[bold red]miniBravos Agent[/bold red]"))
    console.print(f"[bold]Target:[/bold] {TARGET}   [bold]Scope:[/bold] {SCOPE}\n")

    console.print("[cyan]Connecting to CXG MCP server...[/cyan]")
    try:
        async with MCPClient() as client:
            console.print("[green]Connected.[/green]\n")
            await _agent_loop(client)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


async def _agent_loop(client: MCPClient):
    _token_usage["prompt_tokens"] = 0
    _token_usage["completion_tokens"] = 0
    _token_usage["total_tokens"] = 0

    # ------------------------------------------------------------------
    # Phase 1 — Recon (web targets only)
    # ------------------------------------------------------------------
    recon_data = {}
    browser = None
    page = None

    if TARGET_TYPE == "web":
        console.print("[cyan]Phase 1 — Running recon crawler...[/cyan]\n")
        recon_data, browser, page = await run_recon(TARGET_URL)

        ep_count = len(recon_data.get("endpoints", []))
        form_count = len(recon_data.get("forms", []))
        xhr_count = len(recon_data.get("client_behaviour", []))
        console.print(Panel(
            f"Endpoints crawled: {ep_count}\n"
            f"Forms found:       {form_count}\n"
            f"XHR/fetch calls:   {xhr_count}",
            title="[bold]Recon Summary[/bold]",
            border_style="blue",
        ))

    try:
        # ------------------------------------------------------------------
        # Phase 2 — Detection (LLM → CXG)
        # ------------------------------------------------------------------

        # --- Discover available tools ---
        tools = await client.list_tools()
        tools_summary = "\n".join(f"- {t.name}: {t.description}" for t in tools)

        if VERBOSE_REASONING:
            console.print(Panel(
                tools_summary,
                title="[bold]CXG Tools Discovered[/bold]",
                border_style="blue",
            ))

        SCAN_TOOLS = {"cxg_scan", "cxg_template_test"}
        scan_tools_summary = "\n".join(
            f"- {t.name}: {t.description}" for t in tools if t.name in SCAN_TOOLS
        )

        # --- Ask LLM to pick the right tool/template ---
        console.print("[cyan]Phase 2 — Asking model to select the best approach...[/cyan]\n")

        has_inputs = bool(recon_data.get("inputs") or recon_data.get("forms"))
        recon_context = (
            f"\nRecon summary:\n{_recon_summary(recon_data)}\n"
            + (
                "Web inputs and forms were found. Prefer cxg_template_test with a targeted template "
                "(e.g. xss-detection-c, sql-injection-basic) over a broad cxg_scan. "
                "Include a 'template_id' key in your arguments with the template ID.\n"
                if has_inputs else ""
            )
            if recon_data else ""
        )

        selection_prompt = [
            {
                "role": "system",
                "content": (
                    "You are a security scanning agent. You must pick one of the listed tools to scan the target. "
                    "Reply with ONLY a valid JSON object using double quotes. No explanation. No markdown. "
                    "The arguments object must contain 'target' and 'scope'. For cxg_template_test also include 'template_id' with the template ID. "
                    "Format: {\"tool_name\": \"<name>\", \"arguments\": {\"target\": \"<target>\", \"scope\": \"<scope>\", \"template_id\": \"<id_or_omit>\"}, \"reasoning\": \"<one sentence>\"}"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Target: {TARGET}\nScope: {SCOPE}\n"
                    f"{recon_context}"
                    f"Available scan tools:\n{scan_tools_summary}\n\n"
                    "Reply with JSON only. Use the target and scope values exactly as given. "
                    "Arguments must contain only 'target' and 'scope'."
                ),
            },
        ]

        raw_selection = await llm(selection_prompt)

        if VERBOSE_REASONING:
            console.print(Panel(raw_selection, title="[bold]LLM Reasoning[/bold]", border_style="yellow"))

        try:
            selection = parse_llm_json(raw_selection)
            tool_name = selection["tool_name"]
            arguments = {k: v for k, v in selection["arguments"].items() if k in ("target", "scope", "template_id")}
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
                        "Format: {\"tool_name\": \"<name>\", \"arguments\": {\"target\": \"<target>\", \"scope\": \"<scope>\"}, \"reasoning\": \"<one sentence>\"}"
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

        # --- Inject session cookies so CXG can reach authenticated pages ---
        session_cookies = recon_data.get("session_cookies", [])
        if session_cookies and TARGET_LOGIN_URL:
            arguments["cookies"] = "; ".join(
                f"{c['name']}={c['value']}" for c in session_cookies
            )

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
            match = re.search(r"text='(\{.*\})'", raw_output, re.DOTALL)
            if match:
                text_content = match.group(1).encode().decode("unicode_escape")
                scan_json = json.loads(text_content)
            else:
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

        # ------------------------------------------------------------------
        # Phase 3 — Validation (LLM-guided, Playwright-executed)
        # ------------------------------------------------------------------
        validation_results = []

        high_critical = [
            f for f in findings if f["severity"] in ("medium", "high", "critical")
        ]
        vuln_endpoints = []

        # Also trigger Phase 3 when recon discovered known vulnerability paths,
        # even if CXG returned no high/critical findings (CXG can't auth).
        vuln_endpoints = [
            ep for ep in recon_data.get("endpoints", [])
            if any(hint in ep.lower() for hint in VULN_PATH_HINTS)
        ]


        if TARGET_TYPE == "web" and page and (high_critical or vuln_endpoints):
            console.print("\n[cyan]Phase 3 — Proposing verification steps...[/cyan]\n")

            # Probe session validity — navigate to a protected page and check for redirect.
            await page.goto(TARGET_URL, timeout=10000)
            if "login" in page.url.lower():
                console.print("[yellow]Session expired — re-authenticating...[/yellow]")
                await ensure_session(page)

            allowed_actions = list(VERIFICATION_REGISTRY.keys())
            verification_prompt = [
                {
                    "role": "system",
                    "content": (
                        "You are a security validation agent. Given a list of findings, propose verification steps. "
                        "Reply with ONLY a valid JSON array of objects using double quotes. No explanation. No markdown. "
                        "Each object must have keys: \"action\", \"endpoint\", \"payload\", \"notes\". "
                        f"Allowed action values: {json.dumps(allowed_actions)}"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Target URL: {TARGET_URL}\n"
                        f"High/critical findings from scanner:\n{json.dumps(high_critical, indent=2)}\n\n"
                        f"Vulnerability endpoints discovered by recon:\n{json.dumps(vuln_endpoints[:20], indent=2)}\n\n"
                        f"Available verification actions: {', '.join(allowed_actions)}\n\n"
                        "Use this exact endpoint → action mapping. No exceptions:\n"
                        "  URL contains 'xss_s'         → verify_stored_xss\n"
                        "  URL contains 'xss'           → verify_reflected_xss\n"
                        "  URL contains 'sqli'          → verify_sql_injection\n"
                        "  URL contains 'brute' or 'authbypass' or 'login' → verify_auth_bypass\n"
                        "  URL contains 'exec', 'upload', 'fi/', 'captcha', 'csp', 'javascript',\n"
                        "               'open_redirect', 'cryptography', 'api' → SKIP, do not include\n"
                        "Do NOT use verify_log_injection unless the URL explicitly contains 'log'.\n"
                        "Only include endpoints that match the first four rules above.\n"
                        "Reply with JSON array only."
                    ),
                },
            ]

            raw_verification = await llm(verification_prompt)
            if VERBOSE_REASONING:
                console.print(Panel(
                    raw_verification,
                    title="[bold]Verification Plan[/bold]",
                    border_style="magenta",
                ))

            try:
                verification_plan = parse_llm_json(raw_verification)
                if not isinstance(verification_plan, list):
                    verification_plan = [verification_plan]
            except Exception:
                verification_plan = []

            for action_dict in verification_plan:
                try:
                    v_action = VerificationAction(
                        action=action_dict["action"],
                        endpoint=action_dict["endpoint"],
                        payload=action_dict["payload"],
                        notes=action_dict.get("notes", ""),
                    )
                except (KeyError, TypeError):
                    continue

                if v_action.action not in VERIFICATION_REGISTRY:
                    console.print(f"[yellow]Unknown action '{v_action.action}' — skipping.[/yellow]")
                    continue

                console.print(Panel(
                    f"[bold]Action:[/bold]   {v_action.action}\n"
                    f"[bold]Endpoint:[/bold] {v_action.endpoint}\n"
                    f"[bold]Payload:[/bold]  {v_action.payload}\n"
                    f"[bold]Notes:[/bold]    {v_action.notes}",
                    title="[bold yellow]Checkpoint — Approve Verification?[/bold yellow]",
                    border_style="yellow",
                ))

                v_approval = Prompt.ask("Run verification?", choices=["y", "n"], default="n")

                if v_approval == "n":
                    validation_results.append({
                        "action": asdict(v_action),
                        "result": {
                            "exploit_attempted": False,
                            "success_signal": "skipped by user",
                            "confidence": "none",
                        },
                        "status": "PENDING",
                    })
                    continue

                verify_fn = VERIFICATION_REGISTRY[v_action.action]
                v_result = await verify_fn(page, v_action.endpoint, v_action.payload)
                status = (
                    "CONFIRMED EXPLOITABLE"
                    if v_result["confidence"] in ("high", "medium")
                    else "NOT REPRODUCED"
                )
                validation_results.append({
                    "action": asdict(v_action),
                    "result": v_result,
                    "status": status,
                })

                console.print(
                    f"[bold]Result:[/bold] {status} — {v_result['success_signal']}"
                )

        # --- LLM generates a plain-text summary ---
        console.print("[cyan]Generating summary...[/cyan]\n")
        summary_count = len(findings)
        high = sum(1 for f in findings if f["severity"] in ("medium", "high", "critical"))
        confirmed = sum(
            1 for v in validation_results if v["status"] == "CONFIRMED EXPLOITABLE"
        )

        confirmed_details = [
            f"{v['action']['action']} @ {v['action']['endpoint']}"
            for v in validation_results if v["status"] == "CONFIRMED EXPLOITABLE"
        ]
        not_reproduced = sum(1 for v in validation_results if v["status"] == "NOT REPRODUCED")
        pending = sum(1 for v in validation_results if v["status"] == "PENDING")

        summary_prompt = [
            {
                "role": "system",
                "content": "You are a security analyst. Write a concise 2-3 sentence plain-text summary of a scan result. No JSON, no markdown.",
            },
            {
                "role": "user",
                "content": (
                    f"Target: {TARGET}, Scope: {SCOPE}, Template: {tool_name}.\n"
                    f"Scanner findings: {summary_count} total, {high} high/critical.\n"
                    f"Playwright validation: {confirmed} confirmed exploitable, "
                    f"{not_reproduced} not reproduced, {pending} pending.\n"
                    f"Confirmed exploitable: {confirmed_details}\n"
                    f"Scanner finding titles: {[f['title'] for f in findings[:5]]}"
                ),
            },
        ]
        interpretation = await llm(summary_prompt)

        # --- Save report ---
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "model": MODEL_NAME,
            "target": TARGET,
            "scope": SCOPE,
            "template_used": tool_name,
            "recon_data": recon_data,
            "llm_context": {
                "phase2_recon_summary": _recon_summary(recon_data) if recon_data else "",
                "phase2_selection_prompt": selection_prompt,
                "phase3_vuln_endpoints": vuln_endpoints if TARGET_TYPE == "web" else [],
                "phase3_high_critical_passed": high_critical,
            },
            "findings": findings,
            "validation_results": validation_results,
            "interpretation": interpretation,
            "token_usage": dict(_token_usage),
            "raw_output": raw_output,
        }

        tu = _token_usage
        console.print(Panel(
            f"Prompt tokens:     {tu['prompt_tokens']:>6}\n"
            f"Completion tokens: {tu['completion_tokens']:>6}\n"
            f"Total tokens:      {tu['total_tokens']:>6}",
            title="[bold]Token Usage[/bold]",
            border_style="blue",
        ))

        json_path, html_path = save_report(report_data)

        console.print(Panel(
            f"[green]JSON:[/green] {json_path}\n[green]HTML:[/green] {html_path}",
            title="[bold green]Report Saved[/bold green]",
            border_style="green",
        ))

    finally:
        if browser:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(run())
