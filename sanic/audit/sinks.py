"""投递目标（外部审计记录器）抽象与内置实现。

Sink 契约
=========

``deliver`` 收到一个按 seq 升序排列的批次（:class:`AuditEvent`），必须：

* 正常返回 → 整批视为已确认（all-or-nothing）。
* 抛出 :class:`AuditDeliveryError`：

  - ``accepted_keys`` 中的 ``dedup_key`` 单独确认（部分成功）；
  - 其余事件整批退回、退避重试；
  - ``retryable=False`` 时其余事件直接进入死信，不再重试。
* 抛出其它异常 → 视为不可识别故障，安全重试。

投递箱在崩溃恢复（租约过期）与人工重放后可能重复发送同一业务事件，
因此整体是 at-least-once 语义，接收端必须以 ``dedup_key`` 做幂等。
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

from typing import Any, Awaitable, Callable, Sequence

from sanic.audit.events import AuditEvent


#: 投递函数：输入按 seq 升序的 :class:`AuditEvent` 列表，正常返回或
#: 按模块文档抛出异常。函数可自行调用 ``event.to_envelope()`` 取 JSON。
DeliveryFn = Callable[[list[AuditEvent]], Awaitable[Any]]


class AuditDeliveryError(Exception):
    """投递失败。

    ``accepted_keys`` 为接收端已明确确认的 ``dedup_key`` 集合（部分
    成功）；投递器只把这些事件标记为已确认，其余重试或入死信。
    """

    def __init__(
        self,
        message: str,
        *,
        accepted_keys: frozenset[str] | set[str] = frozenset(),
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.accepted_keys = frozenset(accepted_keys)
        self.retryable = retryable


class AuditSink:
    """Sink 基类。子类实现 :meth:`deliver`。"""

    async def deliver(self, events: Sequence[AuditEvent]) -> None:
        raise NotImplementedError  # noqa

    async def close(self) -> None:  # pragma: no cover - 默认无资源
        return None


class FunctionSink(AuditSink):
    """把任意 ``async fn(events) -> None`` 适配成 sink。

    入参是 :class:`AuditEvent` 对象列表（含 ``seq`` / ``dedup_key`` /
    ``outcome`` 等），需要 JSON 时调用 ``event.to_envelope()``。
    """

    def __init__(self, fn: DeliveryFn) -> None:
        self._fn = fn

    async def deliver(self, events: Sequence[AuditEvent]) -> None:
        await self._fn(list(events))


class HTTPSink(AuditSink):
    """通过 HTTP(S) POST 投递 JSON 批次的内置记录器。

    仅使用标准库（:mod:`urllib` 在线程池中执行），不引入额外依赖。
    需要连接池 / mTLS / 请求签名的生产环境请实现自定义 sink。
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        accepted_status: frozenset[int] = frozenset({200, 202, 204}),
    ) -> None:
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("audit sink url must be http(s)")
        self._url = url
        self._headers = {
            "content-type": "application/json",
            **(headers or {}),
        }
        self._timeout = timeout
        self._accepted_status = accepted_status

    async def deliver(self, events: Sequence[AuditEvent]) -> None:
        body = json.dumps(
            {
                "schema": "sanic-audit-batch/v1",
                "events": [e.to_envelope() for e in events],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._post, body)
        except AuditDeliveryError:
            raise
        except Exception as exc:
            raise AuditDeliveryError(str(exc)) from exc

    def _post(self, body: bytes) -> None:
        request = urllib.request.Request(
            self._url,
            data=body,
            headers=self._headers,
            method="POST",
        )
        try:
            # URL 在构造器已限定为 http(s)，不存在 file:/自定义协议。
            with urllib.request.urlopen(  # nosec B310
                request, timeout=self._timeout
            ) as response:
                status = response.getcode()
        except urllib.error.HTTPError as exc:
            # 服务端有响应但状态码表示失败：读取片段用于退避诊断，
            # 不把响应体写入审计库（可能含敏感信息），只截断留存。
            detail = ""
            try:
                detail = exc.read(200).decode("utf-8", "replace")
            except Exception:
                # 仅诊断片段，读不到不影响失败判定。
                pass  # nosec B110
            if exc.code in self._accepted_status:
                return
            raise AuditDeliveryError(
                f"audit sink returned HTTP {exc.code}: {detail}"
            ) from exc
        if status not in self._accepted_status:
            raise AuditDeliveryError(f"audit sink returned HTTP {status}")
