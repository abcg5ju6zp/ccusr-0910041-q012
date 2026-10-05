"""投递箱管理接口（蓝图）。

端点
====

* ``GET  /stats``                 积压概况与确认水位
* ``GET  /events``                积压事件列表（?status=&limit=&offset=）
* ``GET  /events/<seq:int>``      单条事件详情（载荷同样只有脱敏数据）
* ``POST /events/<seq:int>/replay``  安全重放单条 *未确认* 事件
* ``POST /replay``                按状态批量重放（默认仅死信）
* ``POST /flush``                 立即触发一轮投递并返回最新概况

安全策略
========

* 所有变更类操作（replay / flush）都必须携带管理令牌
  （``Authorization: Bearer <token>`` 或 ``X-Audit-Admin-Token``）。
  未配置令牌时变更接口一律拒绝——默认安全，不能“裸奔重放”。
* 只读接口默认仅允许回环访问（``allow_loopback``），配置了令牌时
  令牌同样有效。无法确认来源地址时拒绝。
* 已确认事件永不重放（存储层也会二次拒绝），避免向接收端重复通知。
"""

from __future__ import annotations

import hmac
import ipaddress

from typing import Any

from sanic.audit.store import AlreadyConfirmed
from sanic.blueprints import Blueprint
from sanic.exceptions import Forbidden, NotFound, Unauthorized
from sanic.response import json


_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

# 仅是头名常量，非密钥值。
_TOKEN_HEADER = "X-Audit-Admin-Token"  # nosec B105


def build_management_blueprint(
    *,
    url_prefix: str = "/_audit",
    admin_token: str | None = None,
    allow_loopback: bool = True,
) -> Blueprint:
    bp = Blueprint("audit-management", url_prefix=url_prefix)

    def _outbox(request: Any):
        outbox = getattr(request.app.ctx, "audit_outbox", None)
        if outbox is None:  # pragma: no cover - 装配错误才会发生
            raise NotFound("audit outbox not configured")
        return outbox

    def _client_ip(request: Any) -> str | None:
        try:
            return request.conn_info.client_ip if request.conn_info else None
        except Exception:
            return None

    def _is_loopback(request: Any) -> bool:
        raw = _client_ip(request)
        if not raw:
            return False
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return False
        return any(addr in net for net in _LOOPBACK_NETWORKS)

    def _presented_token(request: Any) -> str | None:
        header = request.headers.get("authorization", None)
        if header and header.lower().startswith("bearer "):
            return header[7:].strip()
        return request.headers.get(_TOKEN_HEADER.lower(), None)

    def _has_valid_token(request: Any) -> bool:
        if not admin_token:
            return False
        presented = _presented_token(request)
        if not presented:
            return False
        # 常量时间比较，避免令牌比较侧信道。
        return hmac.compare_digest(presented, admin_token)

    def _require_read(request: Any) -> None:
        if _has_valid_token(request):
            return
        if allow_loopback and _is_loopback(request):
            return
        raise Unauthorized("audit management requires admin token")

    def _require_write(request: Any) -> None:
        if not admin_token:
            raise Forbidden(
                "audit management mutations are disabled: configure"
                " admin_token to enable replay"
            )
        if not _has_valid_token(request):
            raise Unauthorized("invalid or missing admin token")

    # ---------------------------------------------------------------- #

    @bp.get("/stats")
    async def _stats(request: Any):
        _require_read(request)
        outbox = _outbox(request)
        return json(await outbox.store.stats())

    @bp.get("/events")
    async def _list_events(request: Any):
        _require_read(request)
        outbox = _outbox(request)
        status = request.args.get("status")
        try:
            limit = int(request.args.get("limit", "50"))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            limit, offset = 50, 0
        rows = await outbox.store.list_backlog(
            status=status, limit=limit, offset=max(0, offset)
        )
        return json({"events": rows, "limit": limit, "offset": offset})

    @bp.get("/events/<seq:int>")
    async def _get_event(request: Any, seq: int):
        _require_read(request)
        outbox = _outbox(request)
        row = await outbox.store.get_event(seq)
        if row is None:
            raise NotFound(f"audit event seq={seq} not found")
        return json(row)

    @bp.post("/events/<seq:int>/replay")
    async def _replay_one(request: Any, seq: int):
        _require_write(request)
        outbox = _outbox(request)
        try:
            replayed = await outbox.store.replay(seq=seq)
        except AlreadyConfirmed as exc:
            raise Forbidden(str(exc)) from exc
        except LookupError as exc:
            raise NotFound(f"audit event seq={exc.args[0]} not found") from exc
        outbox.delivery.kick()
        return json(
            {"replayed": replayed, "count": len(replayed)},
            status=202,
        )

    @bp.post("/replay")
    async def _replay_many(request: Any):
        from sanic.exceptions import BadRequest

        _require_write(request)
        outbox = _outbox(request)
        statuses: tuple[str, ...] = ("dead",)
        parsed: str | tuple[str, ...] | None = None
        try:
            body = request.json
            if isinstance(body, dict):
                value = body.get("status")
                if isinstance(value, str):
                    parsed = value
                elif isinstance(value, list):
                    parsed = tuple(str(v) for v in value)
        except Exception:
            parsed = None
        if parsed:
            allowed = {"dead", "pending", "inflight"}
            requested = (parsed,) if isinstance(parsed, str) else parsed
            statuses = tuple(s for s in requested if s in allowed)
            if not statuses:
                raise BadRequest(
                    "status must be one or more of: dead, pending, inflight"
                )
        replayed = await outbox.store.replay(statuses=statuses)
        outbox.delivery.kick()
        return json({"replayed": replayed, "count": len(replayed)}, status=202)

    @bp.post("/flush")
    async def _flush(request: Any):
        _require_write(request)
        outbox = _outbox(request)
        worked = await outbox.delivery.flush_once()
        return json(
            {"flushed": worked, **(await outbox.store.stats())},
            status=202,
        )

    return bp
