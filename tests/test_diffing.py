"""Test asset diff computation."""
import pytest
from lib_webbh.diffing import compute_diff, DiffResult

def test_compute_diff_new_assets():
    prev = {"sub1.example.com": "hash1", "sub2.example.com": "hash2"}
    curr = {"sub1.example.com": "hash1", "sub2.example.com": "hash2", "sub3.example.com": "hash3"}
    result = compute_diff(prev, curr)
    assert isinstance(result, DiffResult)
    assert result.added == ["sub3.example.com"]
    assert result.removed == []
    assert result.unchanged == ["sub1.example.com", "sub2.example.com"]

def test_compute_diff_removed_assets():
    prev = {"sub1.example.com": "hash1", "sub2.example.com": "hash2"}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.removed == ["sub2.example.com"]
    assert result.added == []

def test_compute_diff_empty_previous():
    prev = {}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.added == ["sub1.example.com"]
    assert len(result.removed) == 0

def test_compute_diff_no_changes():
    prev = {"sub1.example.com": "hash1"}
    curr = {"sub1.example.com": "hash1"}
    result = compute_diff(prev, curr)
    assert result.added == []
    assert result.removed == []
    assert result.unchanged == ["sub1.example.com"]
