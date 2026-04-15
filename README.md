# Password AI

> By [MEOK AI Labs](https://meok.ai) — Password generation, strength analysis, hashing, and crack time estimation

## Installation

```bash
pip install password-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `generate_password`
Generate secure random passwords with customizable character sets.

**Parameters:**
- `length` (int): Password length 4-128 (default: 16)
- `uppercase` (bool): Include uppercase (default: True)
- `lowercase` (bool): Include lowercase (default: True)
- `digits` (bool): Include digits (default: True)
- `symbols` (bool): Include symbols (default: True)
- `exclude_ambiguous` (bool): Exclude ambiguous chars like 0/O/1/l (default: False)
- `count` (int): Number of passwords 1-20 (default: 1)

### `check_strength`
Analyze password strength with detailed scoring, entropy calculation, and feedback.

**Parameters:**
- `password` (str): Password to analyze

### `hash_password`
Hash a password. Algorithms: md5, sha1, sha256, sha512, sha3_256.

**Parameters:**
- `password` (str): Password to hash
- `algorithm` (str): Hash algorithm (default: "sha256")
- `salt` (str): Salt value (auto-generated if empty)

### `estimate_crack_time`
Estimate how long to brute-force a password at a given guess rate.

**Parameters:**
- `password` (str): Password to evaluate
- `guesses_per_second` (float): Attacker's guess rate (default: 10 billion)

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
