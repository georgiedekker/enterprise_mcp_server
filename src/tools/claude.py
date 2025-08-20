from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, List

from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Claude Code SDK (drives the CLI and parses its JSON stream)
# pip install claude-code-sdk
from claude_code_sdk import (
    query,
    ClaudeCodeOptions,
    AssistantMessage,
    TextBlock,
    ResultMessage,
    CLINotFoundError,
    ProcessError,
    CLIJSONDecodeError,
)

load_dotenv()

# FastMCP server instance just for Claude tools
claude_mcp = FastMCP(name="Claude Server")

# ---- Defaults you can tweak safely ----
DEFAULT_OPTIONS = ClaudeCodeOptions(
    max_turns=3,
    system_prompt="You are a helpful assistant.",
    cwd=Path("."),  # project/workdir inside the container
    allowed_tools=["Read", "Write", "Bash"],  # be conservative in prod
    permission_mode="acceptEdits",            # or "plan" / "bypassPermissions"
)

class ClaudeCodeParams(BaseModel):
    prompt: str = Field(..., description="User prompt for Claude Code.")
    system_prompt: Optional[str] = Field(
        default=None, description="Override the system prompt."
    )
    path: Optional[str] = Field(
        default=None, description="Working directory for the run (cwd)."
    )
    allowed_tools: Optional[List[str]] = Field(
        default=None, description="Whitelist tools, e.g. ['Read','Write','Bash']."
    )
    permission_mode: Optional[str] = Field(
        default=None, description="plan | acceptEdits | bypassPermissions"
    )
    max_turns: Optional[int] = Field(
        default=None, ge=1, le=20, description="Cap agent loop iterations."
    )

def _build_options(params: ClaudeCodeParams) -> ClaudeCodeOptions:
    """Merge per-call overrides onto DEFAULT_OPTIONS."""
    return ClaudeCodeOptions(
        max_turns=params.max_turns or DEFAULT_OPTIONS.max_turns,
        system_prompt=params.system_prompt or DEFAULT_OPTIONS.system_prompt,
        cwd=Path(params.path) if params.path else DEFAULT_OPTIONS.cwd,
        allowed_tools=(
            params.allowed_tools if params.allowed_tools is not None else DEFAULT_OPTIONS.allowed_tools
        ),
        permission_mode=params.permission_mode or DEFAULT_OPTIONS.permission_mode,
    )

async def _run_claude_code(params: ClaudeCodeParams) -> str:
    """
    Stream messages from the SDK and return concatenated assistant text.
    Notes:
      • SDK yields structured messages (AssistantMessage, ToolUse, Results).
      • We only accumulate TextBlock content for a simple string return.
    """
    options = _build_options(params)

    # Aggregate assistant text as it streams
    chunks: list[str] = []

    try:
        async for message in query(prompt=params.prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text:
                        chunks.append(block.text)
            elif isinstance(message, ResultMessage):
                # You could inspect message.cost_usd, tool results, etc. here.
                pass

    except CLINotFoundError as e:
        # Claude Code CLI not installed in the image
        raise RuntimeError(
            "Claude Code CLI not found. Ensure @anthropic-ai/claude-code is installed in the container."
        ) from e
    except ProcessError as e:
        # Commonly surfaces auth problems or CLI runtime failures
        hint = ""
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        lower = out.lower()
        if ("run /login" in lower) or ("not authenticated" in lower) or ("invalid api key" in lower):
            hint = (
                " (CLI not logged in: run `claude login` once on this host and persist ~/.claude as a volume)"
            )
        raise RuntimeError(f"Claude Code process failed (exit {e.exit_code}).{hint}\n{out}") from e
    except CLIJSONDecodeError as e:
        # SDK couldn't parse stream-json; surface the raw context
        raise RuntimeError(f"Failed to parse Claude stream: {e}") from e

    return "".join(chunks).strip()

@claude_mcp.tool()
async def claude_code(
    prompt: str,
    system_prompt: Optional[str] = None,
    path: Optional[str] = None,
    allowed_tools: Optional[List[str]] = None,
    permission_mode: Optional[str] = None,
    max_turns: Optional[int] = None,
) -> str:
    """
    Generate / modify code with Claude Code (headless).
    Important:
      • Requires prior interactive `claude login` and a persistent ~/.claude.
      • Uses SDK streaming under the hood (no API key needed for Max login).
    """
    params = ClaudeCodeParams(
        prompt=prompt,
        system_prompt=system_prompt,
        path=path,
        allowed_tools=allowed_tools,
        permission_mode=permission_mode,
        max_turns=max_turns,
    )
    return await _run_claude_code(params)

# Optional: lightweight readiness probe as an MCP tool
@claude_mcp.tool()
async def claude_health() -> str:
    """
    Attempts a minimal headless run to verify CLI install + login.
    Returns 'ok' on success, otherwise raises with details.
    """
    _ = await _run_claude_code(
        ClaudeCodeParams(prompt="ping", max_turns=1, allowed_tools=[], permission_mode="plan")
    )
    return "ok"

if __name__ == "__main__":
    # fastmcp will typically exec this module; keep a simple entrypoint.
    import anyio
    anyio.run(claude_mcp.run)