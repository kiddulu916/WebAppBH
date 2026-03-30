# tests/test_dependency_map.py
import pytest


def test_dependency_map_has_all_workers():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    expected_workers = {
        "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
        "authorization", "session_mgmt", "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side", "chain_worker", "reporting",
    }
    assert set(DEPENDENCY_MAP.keys()) == expected_workers


def test_info_gathering_has_no_deps():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["info_gathering"] == []


def test_config_mgmt_depends_on_info_gathering():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["config_mgmt"] == ["info_gathering"]


def test_authorization_and_session_parallel():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    assert DEPENDENCY_MAP["authorization"] == ["authentication"]
    assert DEPENDENCY_MAP["session_mgmt"] == ["authentication"]


def test_chain_worker_depends_on_all_testing():
    from orchestrator.dependency_map import DEPENDENCY_MAP

    chain_deps = set(DEPENDENCY_MAP["chain_worker"])
    assert chain_deps == {
        "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side",
    }


def test_credential_required_set():
    from orchestrator.dependency_map import CREDENTIAL_REQUIRED

    assert "identity_mgmt" in CREDENTIAL_REQUIRED
    assert "authentication" in CREDENTIAL_REQUIRED
    assert "info_gathering" not in CREDENTIAL_REQUIRED
    assert "error_handling" not in CREDENTIAL_REQUIRED


def test_resolve_effective_no_creds():
    from orchestrator.dependency_map import resolve_effective_dependencies

    effective = resolve_effective_dependencies(has_credentials=False)

    # Credential-required workers should be absent
    assert "identity_mgmt" not in effective
    assert "authentication" not in effective
    assert "authorization" not in effective
    assert "session_mgmt" not in effective
    assert "input_validation" not in effective
    assert "business_logic" not in effective

    # Non-credential workers should remain
    assert "info_gathering" in effective
    assert "config_mgmt" in effective
    assert "error_handling" in effective
    assert "cryptography" in effective
    assert "client_side" in effective
    assert "chain_worker" in effective

    # error_handling should depend on config_mgmt (not on skipped workers)
    assert effective["error_handling"] == ["config_mgmt"]

    # chain_worker should depend only on remaining workers
    chain_deps = set(effective["chain_worker"])
    assert "input_validation" not in chain_deps
    assert "error_handling" in chain_deps


def test_resolve_effective_with_creds():
    from orchestrator.dependency_map import resolve_effective_dependencies

    effective = resolve_effective_dependencies(has_credentials=True)

    # All workers should be present
    assert len(effective) == 13
    assert "identity_mgmt" in effective
    assert "authentication" in effective