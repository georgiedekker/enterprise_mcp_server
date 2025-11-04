from __future__ import annotations

import os
import subprocess
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
    permission_mode="acceptEdits",  # or "plan" / "bypassPermissions"
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
            params.allowed_tools
            if params.allowed_tools is not None
            else DEFAULT_OPTIONS.allowed_tools
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

    # Pre-flight checks
    try:
        await _check_claude_cli_availability()
        await _check_authentication_status()
    except RuntimeError as e:
        return f"❌ Pre-flight check failed: {str(e)}\n\nTo fix this:\n1. Ensure Claude CLI is installed\n2. Run claude_auth_login to authenticate\n3. Check claude_auth_status for details"

    try:
        async for message in query(prompt=params.prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text:
                        chunks.append(block.text)
            elif isinstance(message, ResultMessage):
                # You could inspect message.cost_usd, tool results, etc. here.
                if hasattr(message, "cost_usd") and message.cost_usd > 0:
                    chunks.append(f"\n💰 Request cost: ${message.cost_usd:.4f}")
                pass

    except CLINotFoundError as e:
        # Claude Code CLI not installed in the image
        error_msg = (
            "🚫 Claude Code CLI not found!\n"
            "Installation required:\n"
            "  • Docker: Rebuild with updated Dockerfile\n"
            "  • Local: npm install -g @anthropic-ai/claude-code\n"
            "  • Check PATH includes npm global bin directory"
        )
        raise RuntimeError(error_msg) from e
    except ProcessError as e:
        # Commonly surfaces auth problems or CLI runtime failures
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        lower = out.lower()

        if (
            ("run /login" in lower)
            or ("not authenticated" in lower)
            or ("invalid api key" in lower)
        ):
            error_msg = (
                f"🔐 Authentication required!\n"
                f"Exit code: {e.exit_code}\n"
                f"Output: {out}\n\n"
                f"To authenticate:\n"
                f"  • Use claude_auth_login tool for interactive setup\n"
                f"  • Or run 'claude login' manually in container\n"
                f"  • Credentials will persist in ~/.claude volume"
            )
        elif "permission denied" in lower:
            error_msg = f"🚫 Permission denied (exit {e.exit_code}): {out}"
        elif "timeout" in lower:
            error_msg = f"⏰ Timeout error (exit {e.exit_code}): {out}"
        else:
            error_msg = f"❌ Claude process failed (exit {e.exit_code}): {out}"

        raise RuntimeError(error_msg) from e
    except CLIJSONDecodeError as e:
        # SDK couldn't parse stream-json; surface the raw context
        error_msg = (
            f"🔍 Failed to parse Claude CLI output!\n"
            f"This usually indicates:\n"
            f"  • CLI version mismatch with SDK\n"
            f"  • Corrupted output stream\n"
            f"  • Network connectivity issues\n"
            f"Error details: {e}"
        )
        raise RuntimeError(error_msg) from e
    except Exception as e:
        # Catch-all for unexpected errors
        error_msg = (
            f"💥 Unexpected error during Claude execution: {type(e).__name__}: {str(e)}"
        )
        raise RuntimeError(error_msg) from e

    result = "".join(chunks).strip()

    if not result:
        return "⚠️ Claude responded but produced no text output. This might indicate:\n• The request was processed but resulted in no response\n• All responses were non-text (tool calls, etc.)\n• Check the prompt and parameters"

    return result


async def _check_claude_cli_availability() -> None:
    """Check if Claude CLI is available and accessible"""
    import subprocess

    try:
        result = subprocess.run(
            ["which", "claude"], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            raise RuntimeError("Claude CLI not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Timeout checking Claude CLI availability")
    except FileNotFoundError:
        raise RuntimeError("'which' command not available")


async def _check_authentication_status() -> None:
    """Check if Claude is authenticated"""
    config_file = Path.home() / ".claude" / "config.json"
    if not config_file.exists():
        raise RuntimeError("No authentication config found at ~/.claude/config.json")


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
    Execute Claude Code CLI to generate, modify, or analyze code.

    This tool provides access to Claude's coding capabilities through the official CLI.
    Prerequisites:
    • Claude CLI must be installed (@anthropic-ai/claude-code)
    • Authentication required (use claude_auth_login tool first)
    • Credentials persist in ~/.claude directory

    Args:
        prompt: The task or question for Claude to work on
        system_prompt: Optional system prompt to guide Claude's behavior
        path: Working directory for the operation (defaults to current)
        allowed_tools: List of tools Claude can use (e.g., ['Read', 'Write', 'Bash'])
        permission_mode: 'plan', 'acceptEdits', or 'bypassPermissions'
        max_turns: Maximum number of conversation turns (1-20)

    Returns:
        Claude's response as text, including any analysis or explanations
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
    Test Claude Code CLI installation and authentication status.

    This performs a minimal test to verify:
    • Claude CLI is installed and accessible
    • Authentication is configured properly
    • Basic functionality is working

    Returns:
        'ok' if everything is working, error details otherwise
    """
    _ = await _run_claude_code(
        ClaudeCodeParams(
            prompt="ping", max_turns=1, allowed_tools=[], permission_mode="plan"
        )
    )
    return "ok"


if __name__ == "__main__":
    # fastmcp will typically exec this module; keep a simple entrypoint.
    import anyio

    anyio.run(claude_mcp.run)
