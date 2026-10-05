"""审计投递箱：与 Sanic 生命周期、管理接口的集成测试。"""

from __future__ import annotations

from sanic import Sanic
from sanic.audit import AuditDeliveryError, AuditOutbox
from sanic.response import json as sjson


ADMIN = {"x-audit-admin-token": "t0ken"}


def build_app(tmp_path, sink, **attach_kw):
    app = Sanic("audit-it-" + str(tmp_path).replace("/", "-")[-20:])
    db = str(tmp_path / "audit.db")
    outbox = AuditOutbox.attach(
        app,
        sink,
        db_path=db,
        admin_token="t0ken",
        flush_interval=0.05,
        base_backoff=0.02,
        max_backoff=0.1,
        **attach_kw,
    )

    @app.post("/orders")
    async def create_order(request):
        commit = request.json.get("commit")
        if commit:
            request.ctx.audit_commit = commit
        return sjson(
            {"ok": True}, status=201, headers={"X-Audit-Commit": "hdr-1"}
        )

    @app.get("/failed")
    async def failed(request):
        # 业务失败却试图带提交标识：必须被忽略。
        return sjson(
            {"error": "nope"},
            status=500,
            headers={"X-Audit-Commit": "fake-tx"},
        )

    @app.get("/boom")
    async def boom(request):
        raise RuntimeError("secret=leak-me token=tt")

    return app, outbox


# --------------------------------------------------------------------- #
# 采集：身份 / 路由结果 / 提交标识 / 成败判定
# --------------------------------------------------------------------- #


def test_success_event_carries_identity_route_commit(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    _, resp = app.test_client.post(
        "/orders",
        json={"commit": "tx-77"},
        headers={"x-request-id": "rid-100"},
    )
    assert resp.status == 201
    app.test_client.post("/_audit/flush", headers=ADMIN)

    assert len(delivered) == 1
    env = delivered[0].to_envelope()
    assert env["request_id"] == "rid-100"
    assert env["dedup_key"] == "v1:rid-100"
    assert env["outcome"] == "success"
    assert env["status_code"] == 201
    assert env["business"]["commit"] == "tx-77"  # ctx 优先于响应头
    assert env["route_result"]["matched"] is True
    assert "path" in env["request"]


def test_business_failure_is_not_faked_as_success(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    _, resp = app.test_client.get("/failed")
    assert resp.status == 500
    app.test_client.post("/_audit/flush", headers=ADMIN)

    env = delivered[0].to_envelope()
    assert env["outcome"] == "error"
    assert env["status_code"] == 500
    # 失败响应里的提交头绝不采纳。
    assert "commit" not in env["business"]


def test_exception_recorded_as_error_and_redacted(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    _, resp = app.test_client.get("/boom")
    assert resp.status == 500
    app.test_client.post("/_audit/flush", headers=ADMIN)

    env = delivered[0].to_envelope()
    assert env["outcome"] == "error"
    err = env["business"]["error"]
    assert err["type"] == "RuntimeError"
    assert "leak-me" not in err["message"]
    assert "tt" not in err["message"]
    assert "[REDACTED]" in err["message"]


def test_unmatched_route_recorded_as_client_error(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    _, resp = app.test_client.get("/does-not-exist")
    assert resp.status == 404
    app.test_client.post("/_audit/flush", headers=ADMIN)

    env = delivered[0].to_envelope()
    assert env["outcome"] == "client_error"
    assert env["status_code"] == 404
    assert env["route_result"]["matched"] is False
    assert env["route_name"] is None


def test_sensitive_headers_redacted_end_to_end(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    app.test_client.get(
        "/failed",
        headers={
            "authorization": "Bearer secret-token",
            "cookie": "session=abc",
            "x-request-id": "rid-redact",
        },
    )
    app.test_client.post("/_audit/flush", headers=ADMIN)
    headers = delivered[0].to_envelope()["request"]["headers"]
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert headers.get("x-request-id") == "rid-redact"


# --------------------------------------------------------------------- #
# 去重：重复信号不得产生多条事件
# --------------------------------------------------------------------- #


def test_duplicate_response_signal_dedupes(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, outbox = build_app(tmp_path, sink)

    # 额外再挂一个 response 信号，对同一请求重复记录一次。
    @app.signal("http.lifecycle.response")
    async def duplicate_record(request, response):
        await outbox.record_response(request, response)

    app.test_client.post(
        "/orders", json={"commit": "x"}, headers={"x-request-id": "dup-1"}
    )
    _, stats_resp = app.test_client.get("/_audit/stats", headers=ADMIN)
    # 同一 dedup_key 只有一行（pending/inflight/confirmed 合计为 1）。
    total = sum(
        stats_resp.json[k] for k in ("pending", "inflight", "confirmed")
    )
    assert total == 1


# --------------------------------------------------------------------- #
# 重启持久化
# --------------------------------------------------------------------- #


def test_event_survives_server_stop_start(tmp_path):
    """未投递事件必须跨多次服务启停（模拟进程重启）留存并最终送达。"""
    gate = {"up": False}
    delivered = []

    async def sink(events):
        if not gate["up"]:
            # 记录器尚未就绪：可重试失败，事件留在库里。
            raise AuditDeliveryError("recorder unavailable")
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    # 第 1 个请求周期：落库，但投递失败；周期结束即“进程停止”。
    app.test_client.post("/orders", json={"commit": "restart-tx"})
    _, stats1 = app.test_client.get("/_audit/stats", headers=ADMIN)
    assert stats1.json["max_seq"] == 1
    assert stats1.json["confirmed"] == 0
    # 记录器恢复；在之后的请求周期（全新启停）里 flush，仍能送达。
    gate["up"] = True
    app.test_client.post("/_audit/flush", headers=ADMIN)
    assert len(delivered) == 1
    assert delivered[0].to_envelope()["business"]["commit"] == "restart-tx"


def test_after_send_mode_still_persists(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink, durability="after_send")
    app.test_client.post("/orders", json={"commit": "late"})
    app.test_client.post("/_audit/flush", headers=ADMIN)
    assert len(delivered) == 1
    assert delivered[0].to_envelope()["business"]["commit"] == "late"


# --------------------------------------------------------------------- #
# 管理接口：鉴权、积压查询、安全重放
# --------------------------------------------------------------------- #


def test_management_authz(tmp_path):
    async def sink(events):
        return None

    app, _ = build_app(tmp_path, sink)
    app.test_client.post("/orders", json={})

    # 回环可读
    _, r = app.test_client.get("/_audit/stats")
    assert r.status == 200
    # 写操作缺令牌 / 错令牌
    assert app.test_client.post("/_audit/replay")[1].status_code == 401
    assert (
        app.test_client.post(
            "/_audit/replay", headers={"x-audit-admin-token": "wrong"}
        )[1].status_code
        == 401
    )
    # Bearer 形式也接受
    _, ok = app.test_client.post(
        "/_audit/replay", headers={"authorization": "Bearer t0ken"}
    )
    assert ok.status_code == 202


def test_management_mutations_disabled_without_token(tmp_path):
    async def noop(events):
        return None

    app = Sanic("audit-noadmin")
    AuditOutbox.attach(
        app,
        noop,
        db_path=str(tmp_path / "a.db"),
        management=True,
        admin_token=None,
    )

    @app.get("/x")
    async def x(request):
        return sjson({"ok": True})

    app.test_client.get("/x")
    # 读：回环允许
    assert app.test_client.get("/_audit/stats")[1].status_code == 200
    # 写：未配置令牌一律 403（默认安全，不能裸奔重放）
    assert app.test_client.post("/_audit/replay")[1].status_code == 403
    assert app.test_client.post("/_audit/flush")[1].status_code == 403


def test_management_endpoints_are_exempt_from_audit(tmp_path):
    async def sink(events):
        return None

    app, _ = build_app(tmp_path, sink)
    app.test_client.get("/_audit/stats", headers=ADMIN)
    app.test_client.get("/_audit/events", headers=ADMIN)
    app.test_client.post("/_audit/flush", headers=ADMIN)
    _, r = app.test_client.get("/_audit/stats", headers=ADMIN)
    # 管理请求自身没有产生任何审计事件。
    assert r.json["max_seq"] == 0


def test_backlog_listing_and_detail(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    app.test_client.post(
        "/orders", json={"commit": "c1"}, headers={"x-request-id": "r-1"}
    )
    app.test_client.post("/_audit/flush", headers=ADMIN)  # 确保已确认
    _, listing = app.test_client.get(
        "/_audit/events?status=confirmed", headers=ADMIN
    )
    assert listing.status_code == 200
    events = listing.json["events"]
    assert len(events) == 1 and events[0]["seq"] == 1
    assert events[0]["request_id"] == "r-1"

    _, detail = app.test_client.get("/_audit/events/1", headers=ADMIN)
    assert detail.status_code == 200
    assert detail.json["payload"]["business"]["commit"] == "c1"
    assert (
        app.test_client.get("/_audit/events/999", headers=ADMIN)[1].status_code
        == 404
    )


def test_replay_confirmed_event_is_forbidden(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    app, _ = build_app(tmp_path, sink)
    app.test_client.post("/orders", json={"commit": "done"})
    app.test_client.post("/_audit/flush", headers=ADMIN)  # 确认 seq=1
    _, r = app.test_client.post("/_audit/events/1/replay", headers=ADMIN)
    assert r.status_code == 403
    # 接收端没有收到第二次
    assert len(delivered) == 1


def test_dead_letter_replay_redelivers(tmp_path):
    holder = {"ok": False}
    delivered = []

    async def sink(events):
        if not holder["ok"]:
            raise AuditDeliveryError("permanent", retryable=False)
        delivered.extend(events)

    app, outbox = build_app(tmp_path, sink)
    app.test_client.post("/orders", json={"commit": "revive"})
    app.test_client.post("/_audit/flush", headers=ADMIN)  # 直接死信
    _, dead_stats = app.test_client.get("/_audit/stats", headers=ADMIN)
    assert dead_stats.json["dead"] == 1

    # 修复接收端，重放死信并重投。
    holder["ok"] = True
    _, replay = app.test_client.post("/_audit/replay", headers=ADMIN)
    assert replay.json["count"] == 1
    app.test_client.post("/_audit/flush", headers=ADMIN)
    assert len(delivered) == 1
    assert delivered[0].to_envelope()["business"]["commit"] == "revive"
    _, after = app.test_client.get("/_audit/stats", headers=ADMIN)
    assert after.json["dead"] == 0 and after.json["lag"] == 0
