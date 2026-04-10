"""Session token analysis testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class SessionTokenTester(SessionMgmtTool):
    """Test for session token predictability (WSTG-SESS-001)."""

    name = "session_token_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import sys
import re
import math
from collections import Counter

results = []
base_url = "{base_url}"

try:
    tokens = []

    # Collect multiple session tokens from root
    for i in range(10):
        try:
            resp = httpx.get(base_url, follow_redirects=True, timeout=10, verify=False)
            for cname, cval in resp.cookies.items():
                if any(kw in cname.lower() for kw in ["session", "sid", "token", "auth", "jsessionid", "phpsessid", "asp.net"]):
                    tokens.append(cval)
        except Exception:
            pass

    if not tokens:
        # Try login to get session tokens
        login_paths = ["/login", "/auth/login", "/api/login", "/signin", "/wp-login.php", "/account/login"]
        for path in login_paths:
            try:
                resp = httpx.post(
                    base_url.rstrip("/") + path,
                    data={{"username": "test", "password": "test"}},
                    follow_redirects=True,
                    timeout=10,
                    verify=False
                )
                for cname, cval in resp.cookies.items():
                    if any(kw in cname.lower() for kw in ["session", "sid", "token", "auth"]):
                        tokens.append(cval)
            except Exception:
                pass

    if tokens:
        token = tokens[0]
        token_length = len(token)

        # Calculate Shannon entropy
        char_counts = Counter(token)
        entropy = -sum((count / len(token)) * math.log2(count / len(token)) for count in char_counts.values())
        total_entropy = entropy * token_length

        # Character set analysis
        has_upper = bool(re.search(r"[A-Z]", token))
        has_lower = bool(re.search(r"[a-z]", token))
        has_digit = bool(re.search(r"[0-9]", token))
        has_special = bool(re.search(r"[^A-Za-z0-9]", token))

        # Predictability checks
        is_sequential = token.isdigit() and len(token) > 2 and all(
            int(token[i+1]) - int(token[i]) in (1, -1) for i in range(len(token)-1)
        )
        is_repeating = len(set(token)) <= 3 and len(token) > 4
        is_timestamp = token.isdigit() and len(token) in (10, 13)
        is_hex = bool(re.match(r"^[0-9a-fA-F]+$", token))

        # Check for base64
        is_base64 = bool(re.match(r"^[A-Za-z0-9+/=]+$", token))

        issues = []
        if token_length < 16:
            issues.append(f"Token too short ({{token_length}} chars, minimum 16 recommended)")
        if total_entropy < 128:
            issues.append(f"Low entropy ({{total_entropy:.1f}} bits, minimum 128 recommended)")
        if is_sequential:
            issues.append("Token appears to be sequential")
        if is_repeating:
            issues.append("Token has very low character diversity")
        if is_timestamp:
            issues.append("Token appears to be a Unix timestamp")
        if is_hex and token_length < 32:
            issues.append("Short hex token may be predictable")

        severity = "high" if len(issues) >= 2 else ("medium" if issues else "info")

        if issues:
            results.append({{
                "title": "Weak session token characteristics",
                "description": "; ".join(issues),
                "severity": severity,
                "data": {{
                    "token_length": token_length,
                    "entropy_bits": round(total_entropy, 2),
                    "character_set": {{
                        "uppercase": has_upper,
                        "lowercase": has_lower,
                        "digits": has_digit,
                        "special": has_special,
                        "hex_only": is_hex,
                        "base64": is_base64
                    }},
                    "issues": issues,
                    "sample_tokens_analyzed": len(tokens)
                }}
            }})
        else:
            results.append({{
                "title": "Session token analysis",
                "description": f"Session tokens appear to have adequate randomness ({{total_entropy:.1f}} bits of entropy)",
                "severity": "info",
                "data": {{
                    "token_length": token_length,
                    "entropy_bits": round(total_entropy, 2),
                    "character_set": {{
                        "uppercase": has_upper,
                        "lowercase": has_lower,
                        "digits": has_digit,
                        "special": has_special,
                        "hex_only": is_hex,
                        "base64": is_base64
                    }},
                    "sample_tokens_analyzed": len(tokens)
                }}
            }})

        # Check for token uniqueness across samples
        if len(tokens) > 1:
            unique_tokens = set(tokens)
            if len(unique_tokens) < len(tokens):
                results.append({{
                    "title": "Duplicate session tokens detected",
                    "description": f"Found {{len(tokens) - len(unique_tokens)}} duplicate tokens out of {{len(tokens)}} samples",
                    "severity": "high",
                    "data": {{
                        "total_samples": len(tokens),
                        "unique_tokens": len(unique_tokens)
                    }}
                }})
        else:
            results.append({{
                "title": "Session token analysis",
                "description": f"Session tokens appear to have adequate randomness ({{total_entropy:.1f}} bits of entropy)",
                "severity": "info",
                "data": {{
                    "token_length": token_length,
                    "entropy_bits": round(total_entropy, 2),
                    "character_set": {{
                        "uppercase": has_upper,
                        "lowercase": has_lower,
                        "digits": has_digit,
                        "special": has_special,
                        "hex_only": is_hex,
                        "base64": is_base64
                    }},
                    "sample_tokens_analyzed": len(tokens)
                }}
            }})

        # Check for token uniqueness across samples
        if len(tokens) > 1:
            unique_tokens = set(tokens)
            if len(unique_tokens) < len(tokens):
                results.append({{
                    "title": "Duplicate session tokens detected",
                    "description": f"Found {{len(tokens) - len(unique_tokens)}} duplicate tokens out of {{len(tokens)}} samples",
                    "severity": "high",
                    "data": {{
                        "total_samples": len(tokens),
                        "unique_tokens": len(unique_tokens)
                    }}
                }})
    else:
        results.append({{
            "title": "No session tokens found",
            "description": "Could not identify session cookies for analysis",
            "severity": "info",
            "data": {{"paths_checked": ["root", "/login", "/auth/login", "/api/login", "/signin", "/wp-login.php", "/account/login"]}}
        }})

except Exception as e:
    results.append({{
        "title": "Session token test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
