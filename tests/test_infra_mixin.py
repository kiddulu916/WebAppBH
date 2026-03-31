# tests/test_infra_mixin.py
import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.anyio


def test_mixin_has_proxy_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "request_via_proxy")
    assert hasattr(InfrastructureMixin, "request_direct")


def test_mixin_has_callback_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "register_callback")
    assert hasattr(InfrastructureMixin, "check_callback")
    assert hasattr(InfrastructureMixin, "cleanup_callback")


def test_mixin_has_credential_methods():
    from lib_webbh.infra_mixin import InfrastructureMixin

    assert hasattr(InfrastructureMixin, "get_tester_session")
    assert hasattr(InfrastructureMixin, "get_target_user")
    assert hasattr(InfrastructureMixin, "validate_target_user")
