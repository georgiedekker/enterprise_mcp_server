"""
HTTP utilities for the Enterprise MCP Server.

This module provides utilities for HTTP and SSE functionality.
"""
import logging
from typing import Optional

from fastmcp import FastMCP
from starlette.applications import Starlette

logger = logging.getLogger(__name__)

def create_sse_app(mcp_instance: FastMCP) -> Starlette:
    """
    Creates and configures an SSE Starlette application.
    
    Args:
        mcp_instance: The FastMCP instance to use for SSE functionality
    
    Returns:
        A configured Starlette application for SSE
    """
    logger.info("Creating SSE app")
    
    # Get the SSE app from the FastMCP instance
    sse_app = mcp_instance.sse_app()
    
    # Add any additional middleware or configuration here if needed
    # This is where authentication or custom middleware would be added
    
    return sse_app 