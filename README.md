<div align="center">

# Password Ai MCP

**Password AI MCP Server — Security and password tools.**

[![PyPI](https://img.shields.io/pypi/v/meok-password-ai-mcp)](https://pypi.org/project/meok-password-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Password AI MCP Server — Security and password tools.

## Tools

| Tool | Description |
|------|-------------|
| `generate_password` | Generate secure random passwords. |
| `check_strength` | Analyze password strength with detailed scoring. |
| `hash_password` | Hash a password. Algorithms: md5, sha1, sha256, sha512, sha3_256. |
| `estimate_crack_time` | Estimate how long to brute-force a password at given guess rate. |

## Installation

```bash
pip install meok-password-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "password-ai": {
      "command": "python",
      "args": ["-m", "meok_password_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
