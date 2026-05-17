#!/usr/bin/env bash
# Start the Playwright MCP server for interactive AI-agent testing.
# Use this during development to let Claude Code drive the dashboard UI
# via the mcp__plugin_playwright_playwright__* tools.
#
# Usage: bash dashboard/scripts/start-playwright-mcp.sh
# Then invoke Playwright MCP tools in your Claude Code session.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "[mcp] Starting Playwright MCP server on port 8931..."
npx @playwright/mcp --port 8931 \
  --browser chromium \
  --no-sandbox \
  --base-url "http://localhost:3000"
