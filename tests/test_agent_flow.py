"""
Tests for the agent scan-approval flow.

Covers:
  1. Happy path   — user approves the first suggestion ('y')
  2. Alt path     — user rejects the first suggestion ('n'), approves the alternative ('y')
  3. Abort path   — user rejects both suggestions ('n', 'n')

Run from the project root:
    python -m pytest tests/test_agent_flow.py -v
  or:
    python tests/test_agent_flow.py
"""
import asyncio
import json
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def make_tool(name, description):
    t = MagicMock()
    t.name = name
    t.description = description
    return t


FAKE_TOOLS = [
    make_tool("cxg_scan", "Full port and service scan"),
    make_tool("cxg_template_test", "Template-based lightweight test"),
    make_tool("cxg_manage", "Internal management utility"),
]

SELECTION_JSON = json.dumps({
    "tool_name": "cxg_scan",
    "arguments": {"target": "localhost:6379", "scope": "network"},
    "reasoning": "Full scan is the most thorough option.",
})

ALT_JSON = json.dumps({
    "tool_name": "cxg_template_test",
    "arguments": {"target": "localhost:6379", "scope": "network"},
    "reasoning": "Less intrusive template test.",
})

SUMMARY_TEXT = "No critical findings. The target appears hardened."

FAKE_SCAN_RESULT = MagicMock()
FAKE_SCAN_RESULT.__str__ = lambda self: '{"findings": []}'


def make_client():
    client = MagicMock()
    client.list_tools = AsyncMock(return_value=FAKE_TOOLS)
    client.call_tool = AsyncMock(return_value=FAKE_SCAN_RESULT)
    return client


# ---------------------------------------------------------------------------
# Unit tests — parse_llm_json
# ---------------------------------------------------------------------------

class TestParseLlmJson(unittest.TestCase):
    def setUp(self):
        import agent
        self.parse = agent.parse_llm_json

    def test_clean_json(self):
        raw = '{"tool_name": "cxg_scan", "arguments": {}, "reasoning": "ok"}'
        self.assertEqual(self.parse(raw)["tool_name"], "cxg_scan")

    def test_markdown_fenced(self):
        raw = '```json\n{"tool_name": "cxg_scan", "arguments": {}, "reasoning": "ok"}\n```'
        self.assertEqual(self.parse(raw)["tool_name"], "cxg_scan")

    def test_single_quotes(self):
        raw = "{'tool_name': 'cxg_scan', 'arguments': {}, 'reasoning': 'ok'}"
        self.assertEqual(self.parse(raw)["tool_name"], "cxg_scan")

    def test_unclosed_brace(self):
        raw = '{"tool_name": "cxg_scan", "arguments": {}, "reasoning": "ok"'
        self.assertEqual(self.parse(raw)["tool_name"], "cxg_scan")


# ---------------------------------------------------------------------------
# Case 1 — Happy path: user approves the first suggestion
# ---------------------------------------------------------------------------

class TestHappyPath(unittest.IsolatedAsyncioTestCase):
    """User presses 'y' at the first checkpoint — scan runs with the original tool."""

    async def asyncSetUp(self):
        self.client = make_client()
        self.llm_calls = []

        async def fake_llm(messages):
            self.llm_calls.append(messages)
            # selection call → SELECTION_JSON, summary call → plain text
            return SELECTION_JSON if len(self.llm_calls) == 1 else SUMMARY_TEXT

        self.patches = [
            patch("agent.llm", side_effect=fake_llm),
            patch("agent.Prompt.ask", return_value="y"),
            patch("agent.save_report", return_value=("/tmp/r.json", "/tmp/r.html")),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in self.patches:
            p.stop()

    async def test_original_tool_is_used(self):
        import agent
        await agent._agent_loop(self.client)

        self.client.call_tool.assert_called_once()
        tool_name, _ = self.client.call_tool.call_args[0]
        self.assertEqual(tool_name, "cxg_scan")

    async def test_llm_called_twice_only(self):
        """Selection + summary — no alt-suggestion call."""
        import agent
        await agent._agent_loop(self.client)
        self.assertEqual(len(self.llm_calls), 2)


# ---------------------------------------------------------------------------
# Case 2 — Alt path: user rejects first, approves alternative
# ---------------------------------------------------------------------------

class TestAltPath(unittest.IsolatedAsyncioTestCase):
    """User presses 'n' then 'y' — scan runs with the alternative tool."""

    async def asyncSetUp(self):
        self.client = make_client()
        self.llm_calls = []

        async def fake_llm(messages):
            self.llm_calls.append(messages)
            if len(self.llm_calls) == 1:
                return SELECTION_JSON
            if len(self.llm_calls) == 2:
                return ALT_JSON
            return SUMMARY_TEXT

        self.patches = [
            patch("agent.llm", side_effect=fake_llm),
            patch("agent.Prompt.ask", side_effect=["n", "y"]),
            patch("agent.save_report", return_value=("/tmp/r.json", "/tmp/r.html")),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in self.patches:
            p.stop()

    async def test_alternative_tool_is_used(self):
        import agent
        await agent._agent_loop(self.client)

        self.client.call_tool.assert_called_once()
        tool_name, args = self.client.call_tool.call_args[0]
        self.assertEqual(tool_name, "cxg_template_test")
        self.assertEqual(args["target"], "localhost:6379")

    async def test_llm_called_three_times(self):
        """Selection + alternative + summary."""
        import agent
        await agent._agent_loop(self.client)
        self.assertEqual(len(self.llm_calls), 3)

    async def test_alt_prompt_system_enforces_json(self):
        """Alt-prompt system message must contain JSON-only enforcement."""
        import agent
        await agent._agent_loop(self.client)

        alt_messages = self.llm_calls[1]
        system_msg = next(m["content"] for m in alt_messages if m["role"] == "system")
        self.assertIn("Reply with ONLY", system_msg)
        self.assertIn("No explanation", system_msg)
        self.assertIn("No markdown", system_msg)

    async def test_alt_prompt_excludes_management_tools(self):
        """Alt-prompt must only list scan tools, not cxg_manage."""
        import agent
        await agent._agent_loop(self.client)

        alt_messages = self.llm_calls[1]
        user_msg = next(m["content"] for m in alt_messages if m["role"] == "user")
        self.assertNotIn("cxg_manage", user_msg)
        self.assertIn("cxg_scan", user_msg)
        self.assertIn("cxg_template_test", user_msg)


# ---------------------------------------------------------------------------
# Case 3 — Abort: user rejects both suggestions
# ---------------------------------------------------------------------------

class TestAbortPath(unittest.IsolatedAsyncioTestCase):
    """User presses 'n' twice — no scan should run."""

    async def asyncSetUp(self):
        self.client = make_client()

        async def fake_llm(messages):
            return SELECTION_JSON if "Available scan tools" in messages[-1]["content"] else ALT_JSON

        self.patches = [
            patch("agent.llm", side_effect=fake_llm),
            patch("agent.Prompt.ask", side_effect=["n", "n"]),
            patch("agent.save_report", return_value=("/tmp/r.json", "/tmp/r.html")),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in self.patches:
            p.stop()

    async def test_scan_never_runs(self):
        import agent
        await agent._agent_loop(self.client)
        self.client.call_tool.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
