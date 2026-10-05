"""审计投递箱：HTTPSink、兜底证据、装配校验等边界测试。"""

from __future__ import annotations

import json
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sanic import Sanic
from sanic.audit import (
    AuditDeliveryError,
    AuditEvent,
    AuditOptions,
    AuditOutbox,
    FunctionSink,
    HTTPSink,
    Outcome,
)


# --------------------------------------------------------------------- #
# HTTPSink：真实本地 HTTP 端点
# --------------------------------------------------------------------- #


class _Handler(BaseHTTPRequestHandler):
    status = 202
    received = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        type(self).received.append(
            (self.path, self.headers.get("content-type"), body)
        )
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # 静默测试服务器日志
        pass


class LocalServer:
    def __init__(self, status=202):
        _Handler.status = status
        _Handler.received = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )

    @property
    def url(self):
        port = self.httpd.server_address[1]
        return f"http://127.0.0.1:{port}/ingest"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


async def _make_event():
    return AuditEvent(
        request_id="http-1",
        outcome=Outcome.SUCCESS,
        status_code=200,
        route_name="r",
        payload={"a": 1},
    )


async def test_http_sink_posts_batch_and_accepts_202():
    event = await _make_event()
    with LocalServer(202) as srv:
        sink = HTTPSink(srv.url, timeout=5)
        await sink.deliver([event])
        await sink.close()
    assert len(_Handler.received) == 1
    path, ctype, body = _Handler.received[0]
    assert path == "/ingest"
    assert ctype == "application/json"
    doc = json.loads(body)
    assert doc["schema"] == "sanic-audit-batch/v1"
    assert doc["events"][0]["dedup_key"] == "v1:http-1"


async def test_http_sink_raises_retryable_on_5xx():
    event = await _make_event()
    with LocalServer(503) as srv:
        sink = HTTPSink(srv.url, timeout=5)
        with pytest.raises(AuditDeliveryError) as exc:
            await sink.deliver([event])
        await sink.close()
    assert exc.value.retryable is True


def test_http_sink_rejects_non_http_url():
    with pytest.raises(ValueError):
        HTTPSink("ftp://example.com/x")


# --------------------------------------------------------------------- #
# 兜底证据链：主存储不可写时落 JSONL，绝不静默丢弃
# --------------------------------------------------------------------- #


class _BrokenStore:
    async def enqueue(self, event):
        raise OSError("disk unavailable")


async def test_fallback_evidence_written_when_store_fails(tmp_path):
    options = AuditOptions(db_path=str(tmp_path / "audit.db"))
    outbox = AuditOutbox(
        store=_BrokenStore(),
        delivery=object(),  # 本路径不触碰投递器
        options=options,
    )
    event = await _make_event()
    ok = await outbox._fallback_evidence(event)
    assert ok is True
    fallback = tmp_path / "audit.db.fallback.jsonl"
    lines = fallback.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["dedup_key"] == "v1:http-1"

    # 再失败一条：必须追加而不是覆盖。
    await outbox._fallback_evidence(event)
    lines = fallback.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


# --------------------------------------------------------------------- #
# 装配校验
# --------------------------------------------------------------------- #


def test_attach_is_idempotent(tmp_path):
    async def sink(events):
        return None

    app = Sanic("attach-idem")
    first = AuditOutbox.attach(
        app, sink, db_path=str(tmp_path / "a.db"), management=False
    )
    second = AuditOutbox.attach(
        app, sink, db_path=str(tmp_path / "b.db"), management=False
    )
    assert first is second
    assert first.options.db_path == str(tmp_path / "a.db")


def test_attach_requires_sink(tmp_path):
    app = Sanic("attach-nosink")
    with pytest.raises(ValueError):
        AuditOutbox.attach(
            app, None, db_path=str(tmp_path / "a.db"), management=False
        )


def test_attach_rejects_bad_durability(tmp_path):
    async def sink(events):
        return None

    app = Sanic("attach-baddur")
    with pytest.raises(ValueError):
        AuditOutbox.attach(
            app,
            sink,
            db_path=str(tmp_path / "a.db"),
            management=False,
            durability="nonsense",
        )


def test_function_sink_receives_event_objects(tmp_path):
    import asyncio

    seen = []

    async def recorder(events):
        seen.extend(events)

    async def run():
        event = AuditEvent(
            request_id="obj-1",
            outcome=Outcome.SUCCESS,
            status_code=200,
            route_name="r",
            payload={},
        )
        await FunctionSink(recorder).deliver([event])

    asyncio.new_event_loop().run_until_complete(run())
    assert isinstance(seen[0], AuditEvent)
    assert seen[0].dedup_key == "v1:obj-1"
