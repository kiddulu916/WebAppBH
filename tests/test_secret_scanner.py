"""Test secret scanning in tool output."""
from lib_webbh.secret_scanner import scan_text, SecretMatch


def test_detect_aws_access_key():
    text = "found key: AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    assert len(matches) == 1
    assert matches[0].pattern_name == "aws_access_key"


def test_detect_github_token():
    text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
    matches = scan_text(text)
    names = [m.pattern_name for m in matches]
    assert "github_token" in names


def test_detect_jwt():
    text = "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    matches = scan_text(text)
    names = [m.pattern_name for m in matches]
    assert "jwt_token" in names


def test_detect_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn"
    matches = scan_text(text)
    names = [m.pattern_name for m in matches]
    assert "private_key" in names


def test_detect_stripe_key():
    text = "STRIPE_KEY=sk_test_abcdefghijklmnopqrstuvwx"
    matches = scan_text(text)
    names = [m.pattern_name for m in matches]
    assert "stripe_key" in names


def test_no_false_positives():
    text = "This is a normal log line with no secrets.\nJust some regular output here."
    matches = scan_text(text)
    assert matches == []


def test_multiple_secrets_same_line():
    text = "AKIAIOSFODNN7EXAMPLE sk_test_abcdefghijklmnopqrstuvwx"
    matches = scan_text(text)
    names = [m.pattern_name for m in matches]
    assert "aws_access_key" in names
    assert "stripe_key" in names
    assert len(matches) >= 2


def test_redaction():
    text = "found key: AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    assert len(matches) == 1
    val = matches[0].matched_value
    # 20 chars > 16, so redacted as first 8 + ... + last 4
    assert val == "AKIAIOSF...MPLE"


def test_line_numbers():
    text = "line one\nAKIAIOSFODNN7EXAMPLE\nline three\nsk_test_abcdefghijklmnopqrstuvwx"
    matches = scan_text(text)
    line_map = {m.pattern_name: m.line_number for m in matches}
    assert line_map["aws_access_key"] == 2
    assert line_map["stripe_key"] == 4
