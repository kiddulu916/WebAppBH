# orchestrator/dependency_map.py

DEPENDENCY_MAP = {
    "info_gathering":   [],
    "config_mgmt":      ["info_gathering"],
    "identity_mgmt":    ["config_mgmt"],
    "authentication":   ["identity_mgmt"],
    "authorization":    ["authentication"],
    "session_mgmt":     ["authentication"],
    "input_validation": ["authorization", "session_mgmt"],
    "error_handling":   ["config_mgmt"],
    "cryptography":     ["config_mgmt"],
    "business_logic":   ["authorization", "session_mgmt"],
    "client_side":      ["config_mgmt"],
    "chain_worker":     [
        "input_validation", "error_handling",
        "cryptography", "business_logic", "client_side",
    ],
    "reasoning":        ["chain_worker"],
    "reporting":        ["reasoning"],
}

CREDENTIAL_REQUIRED = {
    "identity_mgmt", "authentication", "authorization",
    "session_mgmt", "input_validation", "business_logic",
}


def resolve_effective_dependencies(has_credentials: bool) -> dict[str, list[str]]:
    """Resolve the dependency graph accounting for skipped workers."""
    effective = {}
    for worker, deps in DEPENDENCY_MAP.items():
        if worker in CREDENTIAL_REQUIRED and not has_credentials:
            continue

        resolved_deps = set()
        for dep in deps:
            if dep in CREDENTIAL_REQUIRED and not has_credentials:
                resolved_deps.update(
                    _resolve_skipped(dep, DEPENDENCY_MAP, CREDENTIAL_REQUIRED)
                )
            else:
                resolved_deps.add(dep)

        effective[worker] = sorted(resolved_deps)

    return effective


def _resolve_skipped(worker, dep_map, skip_set):
    result = set()
    for dep in dep_map.get(worker, []):
        if dep in skip_set:
            result.update(_resolve_skipped(dep, dep_map, skip_set))
        else:
            result.add(dep)
    return result