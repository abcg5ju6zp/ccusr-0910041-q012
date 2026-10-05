"""审计投递箱：存储、投递器、事件与脱敏的单元测试。

注：环境内 pytest-asyncio 0.20 与 pytest 9 的异步 fixture 不兼容，
故异步资源一律通过 ``async with AuditStore(...)`` 在测试体内创建。
"""

from __future__ import annotations

import asyncio
import time

import pytest

from sanic.audit import (
    REDACTED,
    AuditDeliveryError,
    AuditEvent,
    AuditStore,
    FunctionSink,
    OutboxDeliveryService,
    Outcome,
)
from sanic.audit.redaction import (
    redact_mapping,
    safe_headers,
    scrub_text,
)
from sanic.audit.store import (
    STATUS_DEAD,
    STATUS_PENDING,
    AlreadyConfirmed,
)


def make_event(request_id="r1", **kw):
    return AuditEvent(
        request_id=request_id,
        outcome=kw.pop("outcome", Outcome.SUCCESS),
        status_code=kw.pop("status_code", 200),
        route_name=kw.pop("route_name", "bp.handler"),
        payload=kw.pop("payload", {"k": "v"}),
        **kw,
    )


# --------------------------------------------------------------------- #
# 事件模型 / 去重键 / 结局判定
# --------------------------------------------------------------------- #


def test_dedup_key_stable_per_request():
    e1 = make_event("req-7")
    e2 = make_event("req-7")
    e3 = make_event("req-8")
    assert e1.dedup_key == e2.dedup_key == "v1:req-7"
    assert e3.dedup_key == "v1:req-8"
    # 每次构造的 event_id 不同，但 dedup_key 相同。
    assert e1.event_id != e2.event_id


@pytest.mark.parametrize(
    "status,expected",
    [
        (200, Outcome.SUCCESS),
        (201, Outcome.SUCCESS),
        (204, Outcome.SUCCESS),
        (400, Outcome.CLIENT_ERROR),
        (404, Outcome.CLIENT_ERROR),
        (500, Outcome.ERROR),
        (503, Outcome.ERROR),
        (None, Outcome.ERROR),
    ],
)
def test_outcome_from_status(status, expected):
    assert Outcome.from_status(status) is expected


def test_envelope_contains_identity_and_schema():
    env = make_event("req-9").to_envelope()
    assert env["schema"].startswith("sanic-audit/")
    assert env["request_id"] == "req-9"
    assert env["dedup_key"] == "v1:req-9"
    assert env["outcome"] == "success"
    assert env["route_name"] == "bp.handler"
    assert env["k"] == "v"  # 业务字段保留在同一信封


# --------------------------------------------------------------------- #
# 脱敏
# --------------------------------------------------------------------- #


def test_redact_mapping_nested_sensitive():
    data = {
        "Authorization": "Bearer abc",
        "nested": {"token": "t", "ok": 1},
        "items": [{"api_key": "k"}, {"fine": "x"}],
    }
    out = redact_mapping(data)
    assert out["Authorization"] == REDACTED
    assert out["nested"] == {"token": REDACTED, "ok": 1}
    assert out["items"][0] == {"api_key": REDACTED}
    assert out["items"][1] == {"fine": "x"}


def test_scrub_text_inline_secrets():
    text = "login failed secret=hunter2, token: zz for user"
    out = scrub_text(text)
    assert "hunter2" not in out and "zz" not in out
    assert REDACTED in out


def test_safe_headers_whitelist():
    class H:
        def __init__(self, d):
            self._d = {k.lower(): v for k, v in d.items()}

        def getone(self, name):
            return self._d.get(name.lower())

    h = H(
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer x",
            "X-Request-ID": "abc",
            "X-Custom": "drop",
        }
    )
    out = safe_headers(h, allow=frozenset({"content-type", "x-request-id"}))
    assert out == {
        "content-type": "application/json",
        "x-request-id": "abc",
    }
    assert "authorization" not in out and "x-custom" not in out


# --------------------------------------------------------------------- #
# 存储：去重落库
# --------------------------------------------------------------------- #


async def test_enqueue_dedup(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        r1 = await store.enqueue(make_event("dup"))
        r2 = await store.enqueue(make_event("dup"))
        assert r1.inserted is True and r1.seq == 1
        assert r2.inserted is False and r2.duplicate_of == 1
        stats = await store.stats()
        assert stats["max_seq"] == 1 and stats["pending"] == 1


async def test_persistence_across_restart(tmp_path):
    path = str(tmp_path / "a.db")
    async with AuditStore(path) as s1:
        await s1.enqueue(make_event("persist-1"))

    # 模拟进程重启：重新打开同一库，未投递事件仍在。
    async with AuditStore(path) as s2:
        stats = await s2.stats()
        assert stats["pending"] == 1 and stats["max_seq"] == 1
        backlog = await s2.list_backlog()
        assert backlog[0]["request_id"] == "persist-1"


# --------------------------------------------------------------------- #
# 认领 / 确认 / 水位
# --------------------------------------------------------------------- #


async def test_claim_confirm_watermark(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        for i in range(3):
            await store.enqueue(make_event(f"w{i}"))
        claimed = await store.claim_batch(10, lease_seconds=30, batch_id="b")
        assert [s for s, _ in claimed] == [1, 2, 3]
        wm = await store.mark_confirmed([1, 2, 3])
        assert wm == 3
        stats = await store.stats()
        assert stats["confirmed"] == 3 and stats["lag"] == 0


async def test_watermark_does_not_jump_gap(tmp_path):
    """seq=2 先确认也不能越过 seq=1：水位必须连续。"""
    async with AuditStore(str(tmp_path / "a.db")) as store:
        for i in range(3):
            await store.enqueue(make_event(f"g{i}"))
        await store.claim_batch(10, lease_seconds=30, batch_id="b")
        wm = await store.mark_confirmed([2, 3])
        assert wm == 0  # 缺口 seq=1 挡住水位
        wm = await store.mark_confirmed([1])
        assert wm == 3


async def test_lease_expiry_reclaims_inflight(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        await store.enqueue(make_event("lease"))
        claimed = await store.claim_batch(10, lease_seconds=0.02, batch_id="b")
        assert len(claimed) == 1
        assert (await store.stats())["inflight"] == 1
        await asyncio.sleep(0.03)
        assert await store.reclaim_stale(30) == 1
        stats = await store.stats()
        assert stats["pending"] == 1 and stats["inflight"] == 0


# --------------------------------------------------------------------- #
# 投递器：成功、失败退避、死信、部分确认、乱序
# --------------------------------------------------------------------- #


async def test_delivery_success_confirms(tmp_path):
    delivered = []

    async def sink(events):
        delivered.extend(events)

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(store, FunctionSink(sink), batch_size=10)
        await store.enqueue(make_event("d1"))
        assert await svc.flush_once() is True
        assert len(delivered) == 1
        assert delivered[0].seq == 1
        assert (await store.stats())["confirmed"] == 1


async def test_delivery_retry_then_dead_letter(tmp_path):
    calls = 0

    async def always_fail(events):
        nonlocal calls
        calls += 1
        raise AuditDeliveryError("down")

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(
            store,
            FunctionSink(always_fail),
            max_attempts=3,
            base_backoff=0.01,
            max_backoff=0.02,
        )
        await store.enqueue(make_event("dead"))
        for _ in range(3):
            await asyncio.sleep(0.025)
            await svc.flush_once()
        assert calls == 3
        stats = await store.stats()
        assert stats["dead"] == 1 and stats["confirmed"] == 0
        assert stats["lag"] == 1  # 死信也是缺口，水位仍为 0


async def test_delivery_non_retryable_goes_straight_dead(tmp_path):
    async def reject(events):
        raise AuditDeliveryError("400 bad", retryable=False)

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(
            store, FunctionSink(reject), max_attempts=10, base_backoff=1
        )
        await store.enqueue(make_event("perm"))
        await svc.flush_once()
        assert (await store.stats())["dead"] == 1


async def test_partial_accept_preserves_order_gap(tmp_path):
    """接收端只接受 seq 2/3，seq 1 失败：水位停 0，补 seq 1 后追平。"""
    order = []

    async def first_batch(events):
        order.append([e.seq for e in events])
        keys = {e.dedup_key for e in events}
        accepted = {k for k in keys if k != "v1:p0"}
        raise AuditDeliveryError("one bad", accepted_keys=accepted)

    async def second_batch(events):
        order.append([e.seq for e in events])

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(
            store,
            FunctionSink(first_batch),
            base_backoff=0.01,
            max_backoff=0.02,
        )
        for i in range(3):
            await store.enqueue(make_event(f"p{i}"))
        await svc.flush_once()
        assert (await store.stats())["confirmed"] == 2
        assert await store.watermark() == 0
        await asyncio.sleep(0.025)
        svc._sink = FunctionSink(second_batch)
        await svc.flush_once()
        assert await store.watermark() == 3
        assert order == [[1, 2, 3], [1]]  # 严格升序、缺口优先补齐


async def test_envelope_carries_seq_for_reordering(tmp_path):
    seen = []

    async def sink(events):
        seen.extend(e.to_envelope() for e in events)  # events 是 AuditEvent

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(store, FunctionSink(sink))
        await store.enqueue(make_event("s1"))
        await svc.flush_once()
        assert seen[0]["seq"] == 1


# --------------------------------------------------------------------- #
# 重放安全
# --------------------------------------------------------------------- #


async def test_replay_confirmed_is_rejected(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        await store.enqueue(make_event("rr"))
        claimed = await store.claim_batch(10, lease_seconds=30, batch_id="b")
        await store.mark_confirmed([c[0] for c in claimed])
        with pytest.raises(AlreadyConfirmed):
            await store.replay(seq=1)


async def test_replay_dead_resets_for_redelivery(tmp_path):
    async def fail(events):
        raise AuditDeliveryError("x", retryable=False)

    async with AuditStore(str(tmp_path / "a.db")) as store:
        svc = OutboxDeliveryService(store, FunctionSink(fail), max_attempts=1)
        await store.enqueue(make_event("rv"))
        await svc.flush_once()
        assert (await store.stats())["dead"] == 1

        seqs = await store.replay(statuses=(STATUS_DEAD,))
        assert seqs == [1]
        stats = await store.stats()
        assert stats["dead"] == 0 and stats["pending"] == 1
        row = (await store.list_backlog(status=STATUS_PENDING))[0]
        assert row["attempts"] == 0  # 重放清零尝试次数


async def test_replay_unknown_seq_raises(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        with pytest.raises(LookupError):
            await store.replay(seq=999)


async def test_prune_keeps_watermark(tmp_path):
    async with AuditStore(str(tmp_path / "a.db")) as store:
        for i in range(2):
            await store.enqueue(make_event(f"pr{i}"))
        claimed = await store.claim_batch(10, lease_seconds=30, batch_id="b")
        await store.mark_confirmed([c[0] for c in claimed])
        # 直接把确认时间推到很久以前（水位游标独立，不应受影响）。
        store._conn.execute(
            "UPDATE audit_outbox SET updated_at = ?",
            (time.time() - 10000,),
        )
        removed = await store.prune_confirmed(keep_seconds=10)
        assert removed == 2
        assert await store.watermark() == 2
