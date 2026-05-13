# tests/test_stage2_pipeline_wiring.py
"""Tests for Stage 2 pipeline preamble + _run_stage kwargs (Phase 3)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workers.info_gathering.fingerprint_aggregator import ProbeResult
from workers.info_gathering.pipeline import Pipeline, Stage


class _FakeTool:
    """Module-level fake tool so its class survives ``stage.tools = [...]``."""

    captured: dict = {}

    async def execute(self, **kwargs):
        type(self).captured = dict(kwargs)
        return ProbeResult(probe="banner", obs_id=1, signals={})


class TestRunStageKwargs:
    @pytest.mark.anyio
    async def test_run_stage_threads_asset_id_host_intensity(self):
        """_run_stage must pass asset_id/host/intensity into every tool's execute()."""
        _FakeTool.captured = {}
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        stage = Stage(name="web_server_fingerprint", section_id="4.1.2", tools=[_FakeTool])
        target = MagicMock(id=42, base_domain="acme.com")
        scope = MagicMock(_in_scope_patterns=set())

        with patch.object(pipeline, "_classify_pending_assets",
                          new_callable=AsyncMock, return_value=0):
            results = await pipeline._run_stage(
                stage, target, scope_manager=scope,
                headers=None, rate_limiter=None,
                asset_id=501, host="api.acme.com", intensity="medium",
            )

        assert _FakeTool.captured["asset_id"] == 501
        assert _FakeTool.captured["host"] == "api.acme.com"
        assert _FakeTool.captured["intensity"] == "medium"
        assert _FakeTool.captured["target_id"] == 42
        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], ProbeResult)


class TestPipelinePreamble:
    @pytest.mark.anyio
    async def test_run_resolves_subject_asset_and_threads_intensity(self):
        """Pipeline.run() must resolve asset_id once and propagate intensity from playbook."""
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        target = MagicMock(id=42, base_domain="acme.com")
        scope = MagicMock(_in_scope_patterns=set())
        playbook = {"workers": [{"name": "info_gathering", "stages": [
            {"name": "web_server_fingerprint", "enabled": True,
             "config": {"fingerprint_intensity": "high"}},
        ]}]}

        run_stage_capture: dict = {}

        async def fake_run_stage(stage, target, **kwargs):
            run_stage_capture.update(kwargs)
            return []

        with patch.object(pipeline, "_resolve_subject_asset",
                          new_callable=AsyncMock, return_value=501) as ra, \
             patch.object(pipeline, "_run_stage", side_effect=fake_run_stage), \
             patch.object(pipeline, "_get_resume_stage",
                          new_callable=AsyncMock, return_value=None), \
             patch.object(pipeline, "_update_phase", new_callable=AsyncMock), \
             patch.object(pipeline, "_checkpoint_stage", new_callable=AsyncMock), \
             patch.object(pipeline, "_mark_completed", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.push_task", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.FingerprintAggregator") as Agg:
            agg = Agg.return_value
            agg.write_summary = AsyncMock(return_value=99)
            agg.emit_info_leaks = AsyncMock(return_value=[])
            agg._score_slot = MagicMock(
                return_value={"vendor": None, "confidence": 0.0, "signals": [], "conflict": False},
            )
            await pipeline.run(target, scope, playbook=playbook)

        ra.assert_awaited_once_with("acme.com")
        assert run_stage_capture["asset_id"] == 501
        assert run_stage_capture["host"] == "acme.com"
        assert run_stage_capture["intensity"] == "high"

    @pytest.mark.anyio
    async def test_run_invokes_aggregator_for_section_4_1_2(self):
        """After a 4.1.2 stage, run() must call FingerprintAggregator.write_summary."""
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        target = MagicMock(id=42, base_domain="acme.com")
        scope = MagicMock(_in_scope_patterns=set())
        playbook = {"workers": [{"name": "info_gathering", "stages": [
            {"name": "web_server_fingerprint", "enabled": True,
             "config": {"fingerprint_intensity": "low"}},
        ]}]}

        probe_result = ProbeResult(probe="banner", obs_id=7, signals={
            "origin_server": [{"src": "banner.server", "value": "nginx", "w": 0.6}],
            "_raw": {"obs_id": 7, "x_powered_by": "Express",
                     "headers": {"X-Powered-By": "Express"}},
        })

        with patch.object(pipeline, "_resolve_subject_asset",
                          new_callable=AsyncMock, return_value=501), \
             patch.object(pipeline, "_run_stage",
                          new_callable=AsyncMock, return_value=[probe_result]), \
             patch.object(pipeline, "_get_resume_stage",
                          new_callable=AsyncMock, return_value=None), \
             patch.object(pipeline, "_update_phase", new_callable=AsyncMock), \
             patch.object(pipeline, "_checkpoint_stage", new_callable=AsyncMock), \
             patch.object(pipeline, "_mark_completed", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.push_task", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.FingerprintAggregator") as Agg:
            agg = Agg.return_value
            agg.write_summary = AsyncMock(return_value=99)
            agg.emit_info_leaks = AsyncMock(return_value=[100, 101])
            await pipeline.run(target, scope, playbook=playbook)

        Agg.assert_called_once()
        ctor_kwargs = Agg.call_args.kwargs
        assert ctor_kwargs["asset_id"] == 501
        assert ctor_kwargs["target_id"] == 42
        assert ctor_kwargs["intensity"] == "low"
        agg.write_summary.assert_awaited_once_with([probe_result])
        agg.emit_info_leaks.assert_awaited_once()

    @pytest.mark.anyio
    async def test_run_does_not_invoke_aggregator_for_other_sections(self):
        """Aggregator only runs for section_id 4.1.2."""
        pipeline = Pipeline(target_id=42, container_name="info_gathering")
        target = MagicMock(id=42, base_domain="acme.com")
        scope = MagicMock(_in_scope_patterns=set())
        playbook = {"workers": [{"name": "info_gathering", "stages": [
            {"name": "search_engine_recon", "enabled": True},
        ]}]}

        with patch.object(pipeline, "_resolve_subject_asset",
                          new_callable=AsyncMock, return_value=501), \
             patch.object(pipeline, "_run_stage",
                          new_callable=AsyncMock, return_value=[{"found": 3}]), \
             patch.object(pipeline, "_get_resume_stage",
                          new_callable=AsyncMock, return_value=None), \
             patch.object(pipeline, "_update_phase", new_callable=AsyncMock), \
             patch.object(pipeline, "_checkpoint_stage", new_callable=AsyncMock), \
             patch.object(pipeline, "_mark_completed", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.push_task", new_callable=AsyncMock), \
             patch("workers.info_gathering.pipeline.FingerprintAggregator") as Agg:
            await pipeline.run(target, scope, playbook=playbook)

        Agg.assert_not_called()


class TestStage2Registry:
    def test_stage2_tools_are_the_new_probe_set(self):
        from workers.info_gathering.pipeline import STAGES
        s = next(s for s in STAGES if s.name == "web_server_fingerprint")
        tool_names = {cls.__name__ for cls in s.tools}
        assert tool_names == {
            "LivenessProbe", "BannerProbe", "HeaderOrderProbe", "MethodProbe",
            "ErrorPageProbe", "TLSProbe", "WAFProbe", "WhatWeb",
        }
        assert "Nmap" not in tool_names

    def test_stage2_section_id(self):
        from workers.info_gathering.pipeline import STAGES
        s = next(s for s in STAGES if s.name == "web_server_fingerprint")
        assert s.section_id == "4.1.2"
