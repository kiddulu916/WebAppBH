from unittest.mock import MagicMock

from workers.identity_mgmt.concurrency import WeightClass


def test_role_enumerator_is_light():
    from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
    assert RoleEnumerator.weight_class == WeightClass.LIGHT


def test_role_enumerator_build_command():
    from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
    tool = RoleEnumerator()
    target = MagicMock(base_domain="example.com")
    cmd = tool.build_command(target)
    assert isinstance(cmd, list)
    # Placeholder assertion for now


def test_role_enumerator_parse_output():
    from workers.identity_mgmt.tools.role_enumerator import RoleEnumerator
    tool = RoleEnumerator()
    output = "placeholder output"
    results = tool.parse_output(output)
    assert isinstance(results, list)
    assert len(results) == 1
    assert "title" in results[0]


def test_registration_tester_is_light():
    from workers.identity_mgmt.tools.registration_tester import RegistrationTester
    assert RegistrationTester.weight_class == WeightClass.LIGHT


def test_account_provision_tester_is_light():
    from workers.identity_mgmt.tools.account_provision_tester import AccountProvisionTester
    assert AccountProvisionTester.weight_class == WeightClass.LIGHT


def test_account_enumerator_is_light():
    from workers.identity_mgmt.tools.account_enumerator import AccountEnumerator
    assert AccountEnumerator.weight_class == WeightClass.LIGHT


def test_username_policy_tester_is_light():
    from workers.identity_mgmt.tools.username_policy_tester import UsernamePolicyTester
    assert UsernamePolicyTester.weight_class == WeightClass.LIGHT