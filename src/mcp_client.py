from contextlib import AsyncExitStack

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from config import CXG_COMMAND, CXG_ARGS


class MCPClient:
    def __init__(self):
        self.session = None
        self._stack = None

    async def __aenter__(self):
        self._stack = AsyncExitStack()
        params = StdioServerParameters(command=CXG_COMMAND, args=CXG_ARGS)
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()
        return self

    async def __aexit__(self, *args):
        await self._stack.aclose()

    async def list_tools(self):
        result = await self.session.list_tools()
        return result.tools

    async def call_tool(self, name: str, arguments: dict):
        return await self.session.call_tool(name, arguments)
