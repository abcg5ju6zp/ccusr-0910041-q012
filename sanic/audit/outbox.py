"""持久审计投递箱：应用接入门面。

使用方式见 :meth:`AuditOutbox.attach`。采集通过 Sanic 生命周期信号
完成，不侵入业务代码：

* ``http.routing.after`` —— 记录路由结果（命中的路由名 / URI / 方法）；
* ``http.lifecycle.response`` —— 业务响应已确定时组织事件并落库，
  成败由真实响应状态码判定；
* ``http.lifecycle.exception`` —— 响应已部分发送后再抛出异常 / 不会
  再产生错误响应时，以 ``error`` 结局补落一条（去重键保证与后续
  可能出现的响应事件只有一条生效，且先落库者的结局为准）。

持久化时机
==========

默认 ``durability="before_send"``：事件先在本地 SQLite(WAL) 提交，
响应随后才发出。一次本地顺序写通常为亚毫秒~毫秒级，与“在请求里
同步调用外部记录器”的网络往返有本质区别，且保证进程崩溃不丢已
承诺事件。``durability="after_send"`` 改为发送后调度落库，不再
阻塞响应，但崩溃存在一个极小的丢失窗口。
"""

from __future__ import annotations

import asyncio
import logging
import time

from dataclasses import dataclass
from typing import Any

from sanic.audit.delivery import OutboxDeliveryService
from sanic.audit.events import AuditEvent, Outcome
from sanic.audit.redaction import REDACTED, redact_mapping, safe_headers
from sanic.audit.sinks import AuditSink, FunctionSink
from sanic.audit.store import AuditStore
from sanic.http.constants import Stage


logger = logging.getLogger("sanic.audit.outbox")

#: 业务提交标识的默认响应头。业务成功时可通过它声明事务/提交 ID。
DEFAULT_COMMIT_HEADER = "X-Audit-Commit"

#: 允许进入审计载荷的请求头白名单（大小写不敏感）。
DEFAULT_ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "content-type",
        "user-agent",
        "x-request-id",
        "accept",
    }
)

MAX_ERROR_MESSAGE = 500

_CTX_ROUTE = "_audit_route"
_CTX_EXCEPTION = "_audit_exception"
_CTX_RECORDED = "_audit_recorded"


@dataclass
class AuditOptions:
    db_path: str
    durability: str = "before_send"  # before_send | after_send
    commit_header: str = DEFAULT_COMMIT_HEADER
    record_query: bool = False
    record_client_ip: bool = True
    allowed_request_headers: frozenset[str] = DEFAULT_ALLOWED_REQUEST_HEADERS
    exempt_path_prefixes: tuple[str, ...] = ()
    batch_size: int = 100
    flush_interval: float = 1.0
    lease_seconds: float = 60.0
    max_attempts: int = 8
    base_backoff: float = 1.0
    max_backoff: float = 300.0


class AuditOutbox:
    """组合存储与投递服务，对应用暴露记录与管理操作。"""

    def __init__(
        self,
        store: AuditStore,
        delivery: OutboxDeliveryService,
        options: AuditOptions,
    ) -> None:
        self.store = store
        self.delivery = delivery
        self.options = options
        self._started = False
        # after_send 模式下落库任务的强引用，避免被 GC 并支持停机排空。
        self._bg_tasks: set[asyncio.Task] = set()

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #

    async def startup(self) -> None:
        if self._started:
            return
        await self.store.start()
        self.delivery.start()
        self._started = True

    async def shutdown(self) -> None:
        if not self._started:
            return
        # after_send 模式下落库可能仍在进行：先等它们完成，避免
        # 已承诺事件随进程退出而丢失。
        pending = [t for t in self._bg_tasks if not t.done()]
        if pending:
            _, still_pending = await asyncio.wait(pending, timeout=10)
            for task in still_pending:
                logger.critical(
                    "audit: background persistence task did not finish"
                    " during shutdown"
                )
                task.cancel()
        # 再停投递器（优雅地尽量把在飞批次处理完），最后关存储。
        await self.delivery.stop()
        await self.store.close()
        self._started = False

    # ------------------------------------------------------------------ #
    # 事件采集
    # ------------------------------------------------------------------ #

    def remember_route(self, request: Any, route: Any) -> None:
        try:
            setattr(
                request.ctx,
                _CTX_ROUTE,
                {
                    "matched": True,
                    "name": getattr(route, "name", None),
                    "uri": getattr(route, "path", None)
                    or getattr(route, "uri", None),
                    "methods": sorted(
                        m for m in (getattr(route, "methods", None) or [])
                    ),
                },
            )
        except Exception:  # pragma: no cover - 采集本身不得影响请求
            logger.exception("audit: failed to remember route")

    def remember_exception(
        self, request: Any, exception: BaseException
    ) -> None:
        try:
            setattr(request.ctx, _CTX_EXCEPTION, exception)
        except Exception:  # pragma: no cover
            logger.exception("audit: failed to remember exception")

    async def record_response(self, request: Any, response: Any) -> None:
        """业务响应确定：组织事件并持久化。"""
        status_code = getattr(response, "status", None)
        outcome = Outcome.from_status(status_code)
        await self._persist(request, outcome, status_code, response=response)

    async def record_failure_without_response(
        self, request: Any, exception: BaseException
    ) -> None:
        """不会再有响应发出（如响应中途异常）时按 error 落库。"""
        await self._persist(
            request,
            Outcome.ERROR,
            None,
            response=None,
            exception=exception,
        )

    async def _persist(
        self,
        request: Any,
        outcome: Outcome,
        status_code: int | None,
        *,
        response: Any,
        exception: BaseException | None = None,
    ) -> None:
        if getattr(request.ctx, _CTX_RECORDED, False):
            return
        path = getattr(request, "path", "") or ""

        def _exempt(prefix: str) -> bool:
            base = prefix.rstrip("/")
            return path == base or path.startswith(base + "/")

        if any(_exempt(p) for p in self.options.exempt_path_prefixes):
            # 管理接口自身不进审计流，避免查询/重放产生自激事件。
            return
        try:
            event = self._build_event(
                request, outcome, status_code, response, exception
            )
        except Exception:
            # 采集失败绝不影响业务响应；但这是合规故障，必须显眼。
            logger.exception(
                "audit: failed to build event for request %s",
                getattr(request, "id", "?"),
            )
            return

        async def _write() -> bool:
            try:
                result = await self.store.enqueue(event)
                if result.inserted:
                    self.delivery.kick()
                # 未插入 = 同请求已有事件（先落库意志为准），忽略。
                return True
            except Exception:
                logger.critical(
                    "audit: event persistence FAILED for request %s"
                    " route=%s outcome=%s status=%s; attempting fallback",
                    event.request_id,
                    event.route_name,
                    event.outcome,
                    event.status_code,
                    exc_info=True,
                )
                return await self._fallback_evidence(event)

        try:
            setattr(request.ctx, _CTX_RECORDED, True)
        except Exception:
            # 标记失败不得影响落库主流程。
            pass  # nosec B110

        if self.options.durability == "after_send":
            task = asyncio.ensure_future(_write())
            self._bg_tasks.add(task)
            task.add_done_callback(self._bg_tasks.discard)
            return
        # 默认：先落盘，后发响应。
        await _write()

    async def _fallback_evidence(self, event: AuditEvent) -> bool:
        """主存储不可写时的兜底证据链。

        投递箱绝不能静默丢弃承诺过的事件，也绝不能伪造成功：写一条
        JSON Lines 兜底文件（每行一条事件），并打 critical 日志触发
        告警。兜底文件不是投递队列——它是“这里有事件没能进库”的
        合规证据，运维需据此人工核对、补录。返回是否兜底成功。
        """
        path = self.options.db_path + ".fallback.jsonl"
        line = event.to_json()

        def _append() -> None:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

        try:
            # 在线程中做追加写，避免阻塞事件循环；O_APPEND 保证
            # 单行追加的原子性（POSIX，小于 PIPE_BUF 更稳）。
            await asyncio.get_running_loop().run_in_executor(None, _append)
            logger.critical(
                "audit: event for request %s written to fallback file"
                " %s; manual reconciliation required",
                event.request_id,
                path,
            )
            return True
        except Exception:
            logger.critical(
                "audit: BOTH primary store and fallback file failed for"
                " request %s — audit evidence lost, immediate operator"
                " action required",
                event.request_id,
                exc_info=True,
            )
            return False

    # ------------------------------------------------------------------ #
    # 事件组织与脱敏
    # ------------------------------------------------------------------ #

    def _build_event(
        self,
        request: Any,
        outcome: Outcome,
        status_code: int | None,
        response: Any,
        exception: BaseException | None,
    ) -> AuditEvent:
        opts = self.options
        route_info = getattr(request.ctx, _CTX_ROUTE, None) or {
            "matched": False
        }
        if exception is None:
            exception = getattr(request.ctx, _CTX_EXCEPTION, None)

        request_part: dict[str, Any] = {
            "id": str(request.id) if request.id is not None else None,
            "method": request.method,
            "path": request.path,
        }
        if opts.record_query:
            # query 常含凭证类参数：整体也经过递归脱敏，但默认关闭。
            request_part["query_string"] = redact_mapping(
                dict(request.args) if request.args else {}
            )
        if opts.record_client_ip:
            try:
                request_part["client_ip"] = request.client_ip
            except Exception:
                request_part["client_ip"] = None
        request_part["headers"] = safe_headers(
            getattr(request, "headers", None),
            allow=opts.allowed_request_headers,
        )

        business: dict[str, Any] = {}
        commit = self._extract_commit(request, response, outcome)
        if commit is not None:
            business["commit"] = commit
        if exception is not None:
            business["error"] = {
                "type": type(exception).__name__,
                # 异常消息可能含输入数据：截断长度；自定义异常应避免
                # 在消息中放置敏感信息。
                "message": str(exception)[:MAX_ERROR_MESSAGE],
            }

        payload = {
            "request": request_part,
            "route_result": route_info,
            "business": business,
            "recorded_at": time.time(),
        }
        payload = redact_mapping(payload)

        route_name = (
            route_info.get("name") if route_info.get("matched") else None
        )
        return AuditEvent(
            request_id=request.id,
            outcome=outcome,
            status_code=status_code,
            route_name=route_name,
            payload=payload,
        )

    def _extract_commit(
        self,
        request: Any,
        response: Any,
        outcome: Outcome,
    ) -> str | None:
        """读取业务提交标识。只在业务成功时采纳。

        业务失败（4xx/5xx）即便带了提交头/设置了 ctx，也一律忽略，
        防止把失败伪造成成功审计。
        """
        if outcome is not Outcome.SUCCESS:
            return None
        # 优先业务显式设置的 ctx，其次响应头。
        ctx_commit = getattr(request.ctx, "audit_commit", None)
        if ctx_commit:
            return str(ctx_commit)[:200]
        if response is not None:
            try:
                header = response.headers.getone(self.options.commit_header)
                if header:
                    return str(header)[:200]
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------ #
    # 接入
    # ------------------------------------------------------------------ #

    @classmethod
    def attach(
        cls,
        app: Any,
        sink: AuditSink | Any = None,
        *,
        db_path: str = "audit_outbox.db",
        management: bool = True,
        management_prefix: str = "/_audit",
        admin_token: str | None = None,
        allow_loopback: bool = True,
        durability: str = "before_send",
        **delivery_kwargs: Any,
    ) -> "AuditOutbox":
        """把持久投递箱接到 Sanic 应用上。

        ``sink`` 可以是 :class:`AuditSink` 实例或 ``async fn(events)``
        协程函数。重复 attach 同一 app 会返回已有实例。
        """
        existing = getattr(app.ctx, "audit_outbox", None)
        if existing is not None:
            return existing

        if durability not in {"before_send", "after_send"}:
            raise ValueError(
                "durability must be 'before_send' or 'after_send'"
            )
        if sink is None:
            raise ValueError(
                "a sink (AuditSink instance or async callable) is required"
            )
        if not isinstance(sink, AuditSink):
            sink = FunctionSink(sink)

        options = AuditOptions(
            db_path=db_path,
            durability=durability,
            exempt_path_prefixes=((management_prefix,) if management else ()),
            batch_size=delivery_kwargs.get("batch_size", 100),
            flush_interval=delivery_kwargs.get("flush_interval", 1.0),
            lease_seconds=delivery_kwargs.get("lease_seconds", 60.0),
            max_attempts=delivery_kwargs.get("max_attempts", 8),
            base_backoff=delivery_kwargs.get("base_backoff", 1.0),
            max_backoff=delivery_kwargs.get("max_backoff", 300.0),
        )
        store = AuditStore(db_path)
        delivery = OutboxDeliveryService(store, sink, **delivery_kwargs)
        outbox = cls(store, delivery, options)
        app.ctx.audit_outbox = outbox

        _register_signals(app, outbox)
        _register_listeners(app, outbox)
        if management:
            from sanic.audit.management import build_management_blueprint

            app.blueprint(
                build_management_blueprint(
                    url_prefix=management_prefix,
                    admin_token=admin_token,
                    allow_loopback=allow_loopback,
                )
            )
        return outbox


def _register_signals(app: Any, outbox: AuditOutbox) -> None:
    @app.signal("http.routing.after")
    async def _audit_routing_after(request, route, **_: Any) -> None:
        outbox.remember_route(request, route)

    @app.signal("http.lifecycle.response")
    async def _audit_response(request, response, **_: Any) -> None:
        await outbox.record_response(request, response)

    @app.signal("http.lifecycle.exception")
    async def _audit_exception(request, exception, **_: Any) -> None:
        outbox.remember_exception(request, exception)
        # 只有在不会再产生错误响应时才立刻落库：响应已经开始发送
        # （或处于 HANDLER 之后的阶段），handle_exception 会直接放弃
        # 发送，lifecycle.response 不会再来。其余情况等待
        # lifecycle.response 统一落库，结局由真实状态码决定。
        stream = getattr(request, "stream", None)
        responded = bool(getattr(request, "responded", False))
        stage = getattr(stream, "stage", None)
        no_response = responded or (
            stream is not None and stage is not Stage.HANDLER
        )
        if no_response:
            await outbox.record_failure_without_response(request, exception)


def _register_listeners(app: Any, outbox: AuditOutbox) -> None:
    @app.listener("after_server_start")
    async def _audit_start(app: Any) -> None:
        await outbox.startup()

    @app.listener("before_server_stop")
    async def _audit_stop(app: Any) -> None:
        await outbox.shutdown()


__all__ = [
    "AuditOutbox",
    "AuditOptions",
    "DEFAULT_COMMIT_HEADER",
    "REDACTED",
]
