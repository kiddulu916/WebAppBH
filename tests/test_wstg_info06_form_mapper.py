"""Tests for enhanced FormMapper — WSTG-INFO-06."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from workers.info_gathering.tools.form_mapper import FormMapper, _FormParser


class TestFormParser:
    def test_extracts_action_and_method(self):
        p = _FormParser("https://example.com")
        p.feed('<form action="/login" method="POST"><input name="user"></form>')
        assert len(p.forms) == 1
        assert p.forms[0]["action"] == "https://example.com/login"
        assert p.forms[0]["method"] == "POST"

    def test_defaults_method_to_get_when_missing(self):
        p = _FormParser("https://example.com")
        p.feed('<form action="/"><input name="q"></form>')
        assert p.forms[0]["method"] == "GET"

    def test_flags_hidden_inputs_separately(self):
        p = _FormParser("https://example.com")
        p.feed(
            '<form>'
            '<input name="price" type="hidden" value="99">'
            '<input name="card">'
            '</form>'
        )
        assert "price" in p.forms[0]["hidden_fields"]
        assert "card" not in p.forms[0]["hidden_fields"]

    def test_collects_all_inputs_including_hidden(self):
        p = _FormParser("https://example.com")
        p.feed('<form><input name="price" type="hidden"><input name="card"></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert "price" in names
        assert "card" in names

    def test_skips_inputs_without_name_attribute(self):
        p = _FormParser("https://example.com")
        p.feed('<form><input type="submit" value="Go"><input name="email"></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert names == ["email"]

    def test_multiple_forms_collected(self):
        p = _FormParser("https://example.com")
        p.feed(
            '<form action="/a"><input name="x"></form>'
            '<form action="/b"><input name="y"></form>'
        )
        assert len(p.forms) == 2
        assert p.forms[0]["action"] == "https://example.com/a"
        assert p.forms[1]["action"] == "https://example.com/b"

    def test_handles_malformed_tag_without_raising(self):
        p = _FormParser("https://example.com")
        # Missing closing > on first input — parser must not raise
        p.feed('<form><input name="ok"<input name="also_ok"></form>')

    def test_textarea_and_select_collected(self):
        p = _FormParser("https://example.com")
        p.feed('<form><textarea name="msg"></textarea><select name="opt"></select></form>')
        names = [i["name"] for i in p.forms[0]["inputs"]]
        assert "msg" in names
        assert "opt" in names


class TestFormMapper:
    @pytest.mark.anyio
    async def test_no_target_kwarg_returns_zero(self):
        result = await FormMapper().execute(target_id=1)
        assert result == {"found": 0}

    @pytest.mark.anyio
    async def test_hidden_fields_present_in_observation_tech_stack(self):
        mapper = FormMapper()
        html = (
            '<form action="/pay">'
            '<input name="price" type="hidden" value="99">'
            '<input name="card">'
            '</form>'
        )
        target = MagicMock()
        target.base_domain = "example.com"
        captured_obs = {}

        async def capture(asset_id, tech_stack=None, **kw):
            if tech_stack:
                captured_obs.update(tech_stack)
            return 1

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=html), \
             patch.object(mapper, "save_asset", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "save_observation", side_effect=capture), \
             patch.object(mapper, "_write_parameters", new_callable=AsyncMock):
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            await mapper.execute(target_id=1, target=target)

        assert "price" in captured_obs.get("hidden_fields", [])

    @pytest.mark.anyio
    async def test_write_parameters_called_for_found_form(self):
        mapper = FormMapper()
        html = '<form action="/s"><input name="a"><input name="b"></form>'
        target = MagicMock()
        target.base_domain = "example.com"

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=html), \
             patch.object(mapper, "save_asset", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "save_observation", new_callable=AsyncMock, return_value=1), \
             patch.object(mapper, "_write_parameters", new_callable=AsyncMock) as mock_wp:
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            result = await mapper.execute(target_id=1, target=target)

        assert result["found"] == 1
        assert mock_wp.call_count == 1

    @pytest.mark.anyio
    async def test_fetch_failure_continues_without_raising(self):
        mapper = FormMapper()
        target = MagicMock()
        target.base_domain = "example.com"

        with patch("workers.info_gathering.tools.form_mapper.get_session") as mock_gs, \
             patch.object(mapper, "_fetch_html", new_callable=AsyncMock, return_value=None):
            sess = AsyncMock()
            mock_gs.return_value.__aenter__.return_value = sess
            mock_gs.return_value.__aexit__.return_value = False
            mock_result = AsyncMock()
            mock_result.all = MagicMock(return_value=[])
            sess.execute = AsyncMock(return_value=mock_result)
            result = await mapper.execute(target_id=1, target=target)

        assert result == {"found": 0}
