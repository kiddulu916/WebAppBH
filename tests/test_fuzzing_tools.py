# ---------------------------------------------------------------------------
# Permutation tests
# ---------------------------------------------------------------------------

def test_permutation_generates_suffix_variants():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["dev"], "target.com")
    assert "dev-api.target.com" in results
    assert "dev-staging.target.com" in results

def test_permutation_generates_prefix_variants():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["api"], "target.com")
    assert "v1.api.target.com" in results
    assert "v2.api.target.com" in results

def test_permutation_swaps_separators():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(["dev-api"], "target.com")
    assert "dev.api.target.com" in results

def test_permutation_dedup_against_existing():
    from workers.fuzzing_worker.permutation import generate_permutations
    results = generate_permutations(
        ["dev"], "target.com", existing={"dev-api.target.com"},
    )
    assert "dev-api.target.com" not in results
    assert "dev-staging.target.com" in results

def test_permutation_extracts_prefix():
    from workers.fuzzing_worker.permutation import extract_prefix
    assert extract_prefix("dev.target.com", "target.com") == "dev"
    assert extract_prefix("api.staging.target.com", "target.com") == "api.staging"
    assert extract_prefix("target.com", "target.com") is None


# ---------------------------------------------------------------------------
# Sensitive pattern tests
# ---------------------------------------------------------------------------

def test_sensitive_match_env_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.env")
    assert result is not None
    assert result["severity"] == "critical"
    assert result["category"] == "credentials_keys"

def test_sensitive_match_git_config():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.git/config")
    assert result is not None
    assert result["severity"] == "high"
    assert result["category"] == "source_control"

def test_sensitive_match_backup_file():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/index.php.bak")
    assert result is not None
    assert result["severity"] == "medium"

def test_sensitive_no_match():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/about")
    assert result is None

def test_sensitive_match_sql_dump():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/backup.sql")
    assert result is not None
    assert result["severity"] == "critical"

def test_sensitive_match_vim_swap():
    from workers.fuzzing_worker.sensitive_patterns import check_sensitive
    result = check_sensitive("/.index.php.swp")
    assert result is not None
    assert result["severity"] == "medium"
