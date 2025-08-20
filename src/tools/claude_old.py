from dotenv import load_dotenv
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field
from pathlib import Path
import asyncio
import anyio
from claude_code_sdk import query, ClaudeCodeOptions, AssistantMessage, TextBlock

from typing import Optional, list
import os
import subprocess

load_dotenv()

# Create a separate FastMCP instance for tools
claude_mcp = FastMCP(
    allow_anonymous=True,
    server_name="Claude Server",
    on_duplicate_tools="replace"
)

@claude_mcp.tool()
async def claude_code(prompt: str, system_prompt: Optional[str] = None, path: Optional[str] = None, allowed_tools: Optional[list[str]] = None, permission_mode: Optional[str] = None) -> str:
    """Generate code using Claude."""
    return await run_claude(prompt, system_prompt, path, allowed_tools, permission_mode)

options = ClaudeCodeOptions(
    max_turns=3,
    system_prompt="You are a helpful assistant",
    cwd=Path("."),  # Can be string or Path
    allowed_tools=["Read", "Write", "Bash"],
    permission_mode="acceptEdits"
)

async def run_claude(prompt: str, max_turns: Optional[int] = None, system_prompt: Optional[str] = None, path: Optional[str] = None, allowed_tools: Optional[list[str]] = None, permission_mode: Optional[str] = None) -> str:

    response = await ask_claude(
        model="claude-4-sonnet-20250620",
        messages=[
            Message(role="user", content=prompt),
        ],
        options=options,
        if max_turns: options["max_turns"] = max_turns,
        if system_prompt: options["system_prompt"] = system_prompt,
        if path: options["cwd"] = Path(path),
        if allowed_tools: options["allowed_tools"] = allowed_tools,
        if permission_mode: options["permission_mode"] = permission_mode
    )

    return response

async def ask_claude(model: str, messages: list[Message], options: ClaudeCodeOptions) -> str:
    response = await subprocess.run(["claude", messages, options], capture_output=True, text=True)
    print(response.stdout)
    return response.stdout

if __name__ == "__main__":
    asyncio.run(ask_claude("claude-4-sonnet-20250620", [Message(role="user", content="Hello, how are you?")], ClaudeCodeOptions(max_turns=3, system_prompt="You are a helpful assistant", cwd=Path("."), allowed_tools=["Read", "Write", "Bash"], permission_mode="acceptEdits")))


# #!/usr/bin/env python3
# """Quick start example for Claude Code SDK."""

# import anyio

# from claude_code_sdk import (
#     AssistantMessage,
#     ClaudeCodeOptions,
#     ResultMessage,
#     TextBlock,
#     query,
# )


# async def basic_example():
#     """Basic example - simple question."""
#     print("=== Basic Example ===")

#     async for message in query(prompt="What is 2 + 2?"):
#         if isinstance(message, AssistantMessage):
#             for block in message.content:
#                 if isinstance(block, TextBlock):
#                     print(f"Claude: {block.text}")
#     print()


# async def with_options_example():
#     """Example with custom options."""
#     print("=== With Options Example ===")

#     options = ClaudeCodeOptions(
#         system_prompt="You are a helpful assistant that explains things simply.",
#         max_turns=1,
#     )

#     async for message in query(
#         prompt="Explain what Python is in one sentence.", options=options
#     ):
#         if isinstance(message, AssistantMessage):
#             for block in message.content:
#                 if isinstance(block, TextBlock):
#                     print(f"Claude: {block.text}")
#     print()


# async def with_tools_example():
#     """Example using tools."""
#     print("=== With Tools Example ===")

#     options = ClaudeCodeOptions(
#         allowed_tools=["Read", "Write"],
#         system_prompt="You are a helpful file assistant.",
#     )

#     async for message in query(
#         prompt="Create a file called hello.txt with 'Hello, World!' in it",
#         options=options,
#     ):
#         if isinstance(message, AssistantMessage):
#             for block in message.content:
#                 if isinstance(block, TextBlock):
#                     print(f"Claude: {block.text}")
#         elif isinstance(message, ResultMessage) and message.cost_usd > 0:
#             print(f"\nCost: ${message.cost_usd:.4f}")
#     print()


# async def main():
#     """Run all examples."""
#     await basic_example()
#     await with_options_example()
#     await with_tools_example()


# if __name__ == "__main__":
#     anyio.run(main)