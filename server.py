"""Password AI MCP Server — Security and password tools."""
import hashlib
import math
import re
import secrets
import string
import time
from typing import Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("password-ai-mcp")
_calls: dict[str, list[float]] = {}
DAILY_LIMIT = 50

def _rate_check(tool: str) -> bool:
    now = time.time()
    _calls.setdefault(tool, [])
    _calls[tool] = [t for t in _calls[tool] if t > now - 86400]
    if len(_calls[tool]) >= DAILY_LIMIT:
        return False
    _calls[tool].append(now)
    return True

@mcp.tool()
def generate_password(length: int = 16, uppercase: bool = True, lowercase: bool = True, digits: bool = True, symbols: bool = True, exclude_ambiguous: bool = False, count: int = 1) -> dict[str, Any]:
    """Generate secure random passwords."""
    if not _rate_check("generate_password"):
        return {"error": "Rate limit exceeded (50/day)"}
    if length < 4 or length > 128:
        return {"error": "Length must be 4-128"}
    if count < 1 or count > 20:
        return {"error": "Count must be 1-20"}
    charset = ""
    if uppercase: charset += string.ascii_uppercase
    if lowercase: charset += string.ascii_lowercase
    if digits: charset += string.digits
    if symbols: charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        charset = charset.translate(str.maketrans("", "", "0O1lI|"))
    if not charset:
        return {"error": "At least one character set required"}
    passwords = ["".join(secrets.choice(charset) for _ in range(length)) for _ in range(count)]
    entropy = math.log2(len(charset)) * length
    return {"passwords": passwords, "entropy_bits": round(entropy, 1), "charset_size": len(charset), "length": length}

@mcp.tool()
def check_strength(password: str) -> dict[str, Any]:
    """Analyze password strength with detailed scoring."""
    if not _rate_check("check_strength"):
        return {"error": "Rate limit exceeded (50/day)"}
    score = 0
    feedback = []
    length = len(password)
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    else: feedback.append("Use 16+ characters for strong security")
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    char_types = sum([has_upper, has_lower, has_digit, has_symbol])
    score += char_types
    if char_types < 3: feedback.append("Mix uppercase, lowercase, digits, and symbols")
    # Repeating chars
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("Avoid repeating characters")
    # Sequential
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde)', password.lower()):
        score -= 1
        feedback.append("Avoid sequential characters")
    # Common patterns
    common = ["password", "123456", "qwerty", "admin", "letmein"]
    if any(c in password.lower() for c in common):
        score = 0
        feedback.append("Password contains common patterns")
    score = max(0, min(5, score))
    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
    charset_size = (26 if has_upper else 0) + (26 if has_lower else 0) + (10 if has_digit else 0) + (32 if has_symbol else 0)
    entropy = math.log2(max(charset_size, 1)) * length if charset_size else 0
    return {
        "score": score, "label": labels[score], "entropy_bits": round(entropy, 1),
        "length": length, "has_uppercase": has_upper, "has_lowercase": has_lower,
        "has_digits": has_digit, "has_symbols": has_symbol, "feedback": feedback
    }

@mcp.tool()
def hash_password(password: str, algorithm: str = "sha256", salt: str = "") -> dict[str, Any]:
    """Hash a password. Algorithms: md5, sha1, sha256, sha512, sha3_256."""
    if not _rate_check("hash_password"):
        return {"error": "Rate limit exceeded (50/day)"}
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512, "sha3_256": hashlib.sha3_256}
    if algorithm not in algos:
        return {"error": f"Unsupported algorithm. Use: {', '.join(algos)}"}
    if not salt:
        salt = secrets.token_hex(16)
    salted = salt + password
    h = algos[algorithm](salted.encode()).hexdigest()
    return {"hash": h, "algorithm": algorithm, "salt": salt, "hash_length": len(h)}

@mcp.tool()
def estimate_crack_time(password: str, guesses_per_second: float = 1e10) -> dict[str, Any]:
    """Estimate how long to brute-force a password at given guess rate."""
    if not _rate_check("estimate_crack_time"):
        return {"error": "Rate limit exceeded (50/day)"}
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    charset = (26 if has_upper else 0) + (26 if has_lower else 0) + (10 if has_digit else 0) + (32 if has_symbol else 0)
    charset = max(charset, 1)
    combinations = charset ** len(password)
    seconds = combinations / guesses_per_second / 2  # average case
    if seconds < 1: human = "Instant"
    elif seconds < 60: human = f"{seconds:.1f} seconds"
    elif seconds < 3600: human = f"{seconds/60:.1f} minutes"
    elif seconds < 86400: human = f"{seconds/3600:.1f} hours"
    elif seconds < 31536000: human = f"{seconds/86400:.1f} days"
    elif seconds < 31536000 * 1000: human = f"{seconds/31536000:.1f} years"
    else: human = f"{seconds/31536000:.2e} years"
    return {
        "charset_size": charset, "password_length": len(password),
        "total_combinations": f"{combinations:.2e}", "seconds_to_crack": f"{seconds:.2e}",
        "human_readable": human, "guesses_per_second": f"{guesses_per_second:.0e}"
    }

if __name__ == "__main__":
    mcp.run()
