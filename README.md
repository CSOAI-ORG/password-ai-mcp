# password-ai-mcp

MCP server for password security tools.

## Tools

- **generate_password** — Generate cryptographically secure passwords
- **check_strength** — Analyze password strength with scoring
- **hash_password** — Hash passwords with multiple algorithms + salt
- **estimate_crack_time** — Estimate brute-force crack time

## Usage

```bash
pip install mcp
python server.py
```

## Rate Limits

50 calls/day per tool (free tier).
