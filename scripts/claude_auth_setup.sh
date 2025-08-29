#!/bin/bash

# Claude Code Authentication Setup Script
# This script helps set up authentication for the Claude Code CLI

set -e

echo "========================================="
echo "Claude Code CLI Authentication Setup"
echo "========================================="
echo ""

# Check if running in Docker container
if [ -f /.dockerenv ]; then
    RUNNING_IN_DOCKER=true
    echo "Running in Docker container"
else
    RUNNING_IN_DOCKER=false
    echo "Running on host system"
fi

# Check if Claude CLI is installed
if ! command -v claude &> /dev/null; then
    echo "Error: Claude Code CLI is not installed!"
    echo "Please install it with: npm install -g @anthropic-ai/claude-code"
    exit 1
fi

echo "Claude Code CLI found at: $(which claude)"
echo ""

# Check current authentication status
echo "Checking current authentication status..."
if claude --version &> /dev/null; then
    echo "Claude CLI is accessible"
else
    echo "Warning: Claude CLI may not be properly configured"
fi

# Check if already authenticated
if [ -f "$HOME/.claude/config.json" ]; then
    echo ""
    echo "Found existing Claude configuration at $HOME/.claude/config.json"
    read -p "Do you want to re-authenticate? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing authentication"
        exit 0
    fi
fi

# Perform authentication
echo ""
echo "Starting Claude authentication..."
echo "This will open a browser window for authentication."
echo "Please follow the instructions in your browser."
echo ""

if [ "$RUNNING_IN_DOCKER" = true ]; then
    echo "NOTE: Since you're in a Docker container, you'll need to:"
    echo "1. Copy the URL shown below"
    echo "2. Open it in a browser on your host machine"
    echo "3. Complete the authentication"
    echo "4. The container will automatically detect when auth is complete"
    echo ""
fi

# Run claude login
echo "Running: claude login"
claude login

# Verify authentication
if [ -f "$HOME/.claude/config.json" ]; then
    echo ""
    echo "✓ Authentication successful!"
    echo "Configuration saved to: $HOME/.claude/config.json"
    
    if [ "$RUNNING_IN_DOCKER" = true ]; then
        echo ""
        echo "IMPORTANT: Your authentication is stored in a Docker volume."
        echo "It will persist across container restarts."
    fi
else
    echo ""
    echo "✗ Authentication may have failed."
    echo "Please check the logs and try again."
    exit 1
fi

echo ""
echo "========================================="
echo "Setup complete!"
echo "========================================="