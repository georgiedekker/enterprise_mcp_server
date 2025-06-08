from dotenv import load_dotenv
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field

load_dotenv()

# Create a separate FastMCP instance for tools
tool_mcp = FastMCP(
    allow_anonymous=True,
    server_name="Tool Server",
    on_duplicate_tools="replace"
)

@tool_mcp.tool()  # Use tool_mcp not mcp
def add(a: int, b: int) -> int:
    """Add two integers together."""
    return a + b

@tool_mcp.tool()  # Use tool_mcp not mcp
def subtract(a: int, b: int) -> int:
    """Subtract one integer from another."""
    return a - b