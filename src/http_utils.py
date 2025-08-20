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
    Creates and configures an HTTP/SSE Starlette application.
    
    Args:
        mcp_instance: The FastMCP instance to use for HTTP/SSE functionality
    
    Returns:
        A configured Starlette application for HTTP/SSE
    """
    logger.info("Creating HTTP app (replaces deprecated SSE app)")
    
    # Use the modern http_app method instead of deprecated sse_app
    # As per FastMCP v2.11.3 release notes
    http_app = mcp_instance.http_app()
    
    # Add any additional middleware or configuration here if needed
    # This is where authentication or custom middleware would be added
    
    return http_app 