"""
Phase 1 — Playwright-based recon crawler.

Exports a single coroutine:
    run_recon(target_url) -> (recon_data, browser, page)

The browser is intentionally left open so the caller can reuse the
authenticated session for Phase 3 verification.
Caller is responsible for calling browser.close() when finished.
"""
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright

from config import RECON_MAX_DEPTH, RECON_TIMEOUT, TARGET_LOGIN_URL, TARGET_USERNAME, TARGET_PASSWORD, TARGET_SECURITY_URL, TARGET_SECURITY_LEVEL


async def ensure_session(page) -> bool:
    """
    Check whether the current page is the login wall. If so, re-login and
    restore the security level. Call this at the start of Phase 3 to recover
    from PHP session expiry between recon and verification.
    Returns True if the session is (or becomes) valid.
    """
    if "login" not in page.url.lower():
        return True
    ok = await _login(page, TARGET_LOGIN_URL, TARGET_USERNAME, TARGET_PASSWORD)
    if ok and TARGET_SECURITY_URL and TARGET_SECURITY_LEVEL:
        try:
            await page.goto(TARGET_SECURITY_URL, timeout=RECON_TIMEOUT, wait_until="networkidle")
            await page.select_option("select[name='security']", TARGET_SECURITY_LEVEL)
            await page.click("input[name='seclev_submit'], input[type='submit']")
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
    return ok


async def _login(page, login_url: str, username: str, password: str) -> bool:
    """
    Submit the login form at *login_url* with the given credentials.
    Returns True if the browser moved away from the login page after submit.
    """
    try:
        await page.goto(login_url, timeout=RECON_TIMEOUT, wait_until="networkidle")
        await page.fill("input[name='username']", username)
        await page.fill("input[name='password']", password)
        await page.click("input[type='submit'], button[type='submit'], input[name='Login']")
        await page.wait_for_load_state("networkidle", timeout=8000)
        return "login" not in page.url.lower()
    except Exception:
        return False


async def run_recon(target_url: str):
    """
    BFS-crawl *target_url* up to RECON_MAX_DEPTH levels deep,
    staying within the same origin.

    Returns (recon_data dict, browser, page).
    Session cookies (if login succeeded) are stored in recon_data["session_cookies"].
    """
    result = {
        "endpoints": [],
        "forms": [],
        "headers": {},
        "inputs": [],
        "client_behaviour": [],
        "session_cookies": [],
    }

    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(target_url, 0)]

    playwright_ctx = await async_playwright().start()
    browser = await playwright_ctx.chromium.launch(headless=True)
    page = await browser.new_page()

    def _on_request(request):
        if request.resource_type in ("xhr", "fetch"):
            result["client_behaviour"].append(
                {"method": request.method, "url": request.url}
            )

    page.on("request", _on_request)

    # Log in before crawling so authenticated pages are reachable
    if TARGET_LOGIN_URL:
        await _login(page, TARGET_LOGIN_URL, TARGET_USERNAME, TARGET_PASSWORD)
        # Set security level immediately after login (e.g. DVWA → low)
        if TARGET_SECURITY_URL and TARGET_SECURITY_LEVEL:
            try:
                await page.goto(TARGET_SECURITY_URL, timeout=RECON_TIMEOUT, wait_until="networkidle")
                await page.select_option("select[name='security']", TARGET_SECURITY_LEVEL)
                await page.click("input[name='seclev_submit'], input[type='submit']")
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
        result["session_cookies"] = await page.context.cookies()

    while queue:
        url, depth = queue.pop(0)
        if url in visited or depth > RECON_MAX_DEPTH:
            continue
        visited.add(url)

        try:
            response = await page.goto(
                url, timeout=RECON_TIMEOUT, wait_until="networkidle"
            )
        except Exception:
            continue

        result["endpoints"].append(url)

        if response:
            result["headers"][url] = dict(response.headers)

        # --- Forms and input fields ---
        for form_el in await page.query_selector_all("form"):
            action = await form_el.get_attribute("action") or ""
            method = (await form_el.get_attribute("method") or "get").upper()
            fields = []
            for el in await form_el.query_selector_all("input, select, textarea"):
                name = await el.get_attribute("name") or ""
                ftype = await el.get_attribute("type") or "text"
                fields.append({"name": name, "type": ftype})
                if name:
                    entry = {"url": url, "param": name, "type": ftype}
                    if entry not in result["inputs"]:
                        result["inputs"].append(entry)
            result["forms"].append(
                {
                    "action": urljoin(url, action),
                    "method": method,
                    "fields": fields,
                    "source_page": url,
                }
            )

        # --- Query-string params already present in the URL ---
        qs = urlparse(page.url).query
        for part in (qs.split("&") if qs else []):
            key = part.split("=")[0]
            if key:
                entry = {"url": page.url, "param": key, "type": "query"}
                if entry not in result["inputs"]:
                    result["inputs"].append(entry)

        # --- Enqueue in-scope links for next depth level ---
        if depth < RECON_MAX_DEPTH:
            try:
                links = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
            except Exception:
                links = []
            for link in links:
                if (
                    isinstance(link, str)
                    and link.startswith(origin)
                    and link not in visited
                ):
                    queue.append((link, depth + 1))

    return result, browser, page
