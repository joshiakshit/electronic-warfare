"""Objective 8 scheduler registry tests."""

from __future__ import annotations

import pytest

from ewscan.experiments.registry import build_scheduler, scheduler_names
from ewscan.experiments.runner import _build_scheduler_by_name as runner_scheduler
from ewscan.experiments.sweep import _build_scheduler_by_name as sweep_scheduler


def test_runner_and_sweep_share_the_registry():
    for name in scheduler_names():
        assert runner_scheduler(name).name == build_scheduler(name).name
        assert sweep_scheduler(name).name == build_scheduler(name).name


def test_registry_rejects_unknown_scheduler():
    with pytest.raises(ValueError, match="Unknown scheduler name"):
        build_scheduler("not-a-scheduler")
