try:
    from mcp.server.mcpserver import Context, MCPServer
except ImportError:
    from mcp.server.fastmcp import Context
    from mcp.server.fastmcp import FastMCP as MCPServer

__all__ = ["Context", "MCPServer"]
