"""Shared fixtures. Tests run without any LLM key — they cover the deterministic
components (tools, security, routing fallback, confidence, graph paths)."""
from __future__ import annotations

import pytest


@pytest.fixture
def demo(monkeypatch):
    """Force DEMO_MODE on: tools serve bundled fixtures, no network."""
    monkeypatch.setenv("DEMO_MODE", "true")
    yield


@pytest.fixture
def fast_net(monkeypatch):
    """Live-path tests with httpx mocked: disable rate-limit sleeps and cache."""
    from src.tools import base

    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setattr(base._limiter, "wait", lambda key: None)
    monkeypatch.setattr(base._cache, "enabled", False)
    yield
