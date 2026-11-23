import os
import stat

import httpx
import pytest
import respx
from asyncgh.client import GitHubClient, _cache_storage, _default_cache_path

from asyncgh import API_BASE, GhError

URL = f"{API_BASE}/repos/hugoh/x"
ETAG = '"v1"'


def _first_200_then_304(httpx2_mock: respx.Router):
    return httpx2_mock.get(URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"name": "x"},
                headers={"ETag": ETAG, "Cache-Control": "private, max-age=60"},
            ),
            httpx.Response(304, headers={"ETag": ETAG}),
        ]
    )


async def test_a_repeat_get_revalidates_and_serves_the_body_from_a_304(
    httpx2_mock: respx.Router, tmp_path
):
    route = _first_200_then_304(httpx2_mock)
    async with GitHubClient(cache_path=tmp_path / "http.sqlite") as gh:
        first = await gh.api_json("GET", "/repos/hugoh/x")
        second = await gh.api_json("GET", "/repos/hugoh/x")
    assert first == second == {"name": "x"}
    assert route.call_count == 2
    assert route.calls[1].request.headers["if-none-match"] == ETAG


async def test_cache_survives_a_new_client(httpx2_mock: respx.Router, tmp_path):
    route = _first_200_then_304(httpx2_mock)
    path = tmp_path / "http.sqlite"
    async with GitHubClient(cache_path=path) as gh:
        await gh.api_json("GET", "/repos/hugoh/x")
    async with GitHubClient(cache_path=path) as gh:
        assert await gh.api_json("GET", "/repos/hugoh/x") == {"name": "x"}
    assert route.calls[1].request.headers["if-none-match"] == ETAG


async def test_without_a_cache_path_nothing_is_conditional(
    httpx2_mock: respx.Router,
):
    route = httpx2_mock.get(URL).mock(
        return_value=httpx.Response(200, json={"name": "x"}, headers={"ETag": ETAG})
    )
    async with GitHubClient() as gh:
        await gh.api_json("GET", "/repos/hugoh/x")
        await gh.api_json("GET", "/repos/hugoh/x")
    assert all("if-none-match" not in c.request.headers for c in route.calls)


async def test_requests_still_carry_the_token(httpx2_mock: respx.Router, tmp_path):
    route = _first_200_then_304(httpx2_mock)
    async with GitHubClient(cache_path=tmp_path / "http.sqlite") as gh:
        await gh.api_json("GET", "/repos/hugoh/x")
    assert route.calls[0].request.headers["authorization"] == "Bearer fake-token"


async def test_the_token_is_never_written_to_the_cache_file(
    httpx2_mock: respx.Router, tmp_path
):
    _first_200_then_304(httpx2_mock)
    path = tmp_path / "http.sqlite"
    async with GitHubClient(cache_path=path) as gh:
        await gh.api_json("GET", "/repos/hugoh/x")
        await gh.api_json("GET", "/repos/hugoh/x")
    stored = b"".join(p.read_bytes() for p in tmp_path.iterdir())
    assert b"fake-token" not in stored


async def test_a_changed_resource_returns_the_new_body(
    httpx2_mock: respx.Router, tmp_path
):
    httpx2_mock.get(URL).mock(
        side_effect=[
            httpx.Response(200, json={"v": 1}, headers={"ETag": ETAG}),
            httpx.Response(200, json={"v": 2}, headers={"ETag": '"v2"'}),
        ]
    )
    async with GitHubClient(cache_path=tmp_path / "http.sqlite") as gh:
        assert await gh.api_json("GET", "/repos/hugoh/x") == {"v": 1}
        assert await gh.api_json("GET", "/repos/hugoh/x") == {"v": 2}


def test_default_cache_path_follows_xdg_cache_home(monkeypatch, tmp_path):
    monkeypatch.delenv("ASYNCGH_NO_CACHE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert _default_cache_path() == tmp_path / "asyncgh" / "http.sqlite"


def test_default_cache_path_is_off_when_disabled(monkeypatch):
    monkeypatch.setenv("ASYNCGH_NO_CACHE", "1")
    assert _default_cache_path() is None


async def test_cache_file_is_owner_only_whatever_the_umask_and_directory(
    httpx2_mock: respx.Router, tmp_path
):
    _first_200_then_304(httpx2_mock)
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    path = shared / "http.sqlite"
    path.write_bytes(b"")
    path.chmod(0o644)
    previous = os.umask(0)
    try:
        async with GitHubClient(cache_path=path) as gh:
            await gh.api_json("GET", "/repos/hugoh/x")
            await gh.api_json("GET", "/repos/hugoh/x")
    finally:
        os.umask(previous)
    modes = {p.name: stat.S_IMODE(p.stat().st_mode) for p in shared.iterdir()}
    assert {m for n, m in modes.items() if n.startswith(path.name)} == {0o600}


def test_cache_is_capped_at_50mb_and_expires_after_a_week_by_default(tmp_path):
    gh = GitHubClient(cache_path=tmp_path / "http.sqlite")
    storage = _cache_storage(tmp_path / "http.sqlite", gh._cache_limits)
    assert storage.max_size == 50 * 1024 * 1024
    assert storage.default_ttl == 7 * 24 * 3600


def test_cache_limits_come_from_the_constructor(tmp_path):
    gh = GitHubClient(
        cache_path=tmp_path / "http.sqlite", cache_max_bytes=1024, cache_ttl=60
    )
    storage = _cache_storage(tmp_path / "http.sqlite", gh._cache_limits)
    assert (storage.max_size, storage.default_ttl) == (1024, 60)


def test_cache_limits_come_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("ASYNCGH_CACHE_MAX_BYTES", "2048")
    monkeypatch.setenv("ASYNCGH_CACHE_TTL_SECONDS", "120")
    gh = GitHubClient(cache_path=tmp_path / "http.sqlite")
    storage = _cache_storage(tmp_path / "http.sqlite", gh._cache_limits)
    assert (storage.max_size, storage.default_ttl) == (2048, 120)


def test_constructor_cache_limits_win_over_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("ASYNCGH_CACHE_MAX_BYTES", "2048")
    gh = GitHubClient(cache_path=tmp_path / "http.sqlite", cache_max_bytes=4096)
    assert gh._cache_limits.max_bytes == 4096


def test_a_non_numeric_cache_limit_in_the_environment_is_an_error(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("ASYNCGH_CACHE_TTL_SECONDS", "week")
    with pytest.raises(GhError, match="ASYNCGH_CACHE_TTL_SECONDS"):
        GitHubClient(cache_path=tmp_path / "http.sqlite")
