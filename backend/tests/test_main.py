"""Unit tests for app.main's lifespan startup hook -- specifically the
Tranco popularity-cache fetch, which is deliberately not baked into the
Docker image (see docs/ARCHITECTURE.md's Deployment section) and so must
fail soft if the network is unavailable at container startup."""

import asyncio
from unittest.mock import patch

from app.main import lifespan


class _StubApp:
    pass


def _run_lifespan_once():
    async def _enter_and_exit():
        async with lifespan(_StubApp()):
            pass

    asyncio.run(_enter_and_exit())


def test_lifespan_fetches_tranco_when_missing(tmp_path):
    missing_path = tmp_path / "tranco.csv"
    with (
        patch("app.main.settings.tranco_list_path", missing_path),
        patch("app.main.refresh_cache") as mock_refresh,
    ):
        _run_lifespan_once()
    mock_refresh.assert_called_once()


def test_lifespan_skips_fetch_when_tranco_already_cached(tmp_path):
    existing_path = tmp_path / "tranco.csv"
    existing_path.write_text("1,example.com\n")
    with (
        patch("app.main.settings.tranco_list_path", existing_path),
        patch("app.main.refresh_cache") as mock_refresh,
    ):
        _run_lifespan_once()
    mock_refresh.assert_not_called()


def test_lifespan_does_not_crash_when_tranco_fetch_fails(tmp_path):
    missing_path = tmp_path / "tranco.csv"
    with (
        patch("app.main.settings.tranco_list_path", missing_path),
        patch("app.main.refresh_cache", side_effect=ConnectionError("no network")),
    ):
        _run_lifespan_once()  # must not raise -- this is a fail-soft optional signal
