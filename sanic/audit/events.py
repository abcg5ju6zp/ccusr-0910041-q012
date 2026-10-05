"""审计事件模型。

每个 HTTP 请求在业务响应完成后组织成一条 :class:`AuditEvent`。

去重策略
========

* ``event_id`` 是事件自身的唯一标识（一次性随机 UUID），用于接收端
  追踪单次投递。
* ``dedup_key`` 是业务幂等键，固定为 ``v1:<request_id>``。同一个请求
  无论经过多少条信号路径（正常响应、异常兜底、进程重启后的补写），
  落库时都只有一行，存储层对该键建唯一索引。
* 后台重放只会重置 *未确认* 的事件，已确认事件不允许重放，避免向
  接收端制造重复通知。

业务成败由框架依据真实响应状态码 / 异常判定，业务代码无法通过自定义
响应头把失败声明为成功（详见 :data:`SUCCESS_OUTCOMES`）。
"""

from __future__ import annotations

import enum
import json
import time
import uuid

from typing import Any


# 事件载荷的结构版本，将来不兼容调整时递增。
SCHEMA_VERSION = "sanic-audit/v1"

# 只有这些结局允许采纳业务提交标识。4xx/5xx 即便是业务自己写出的
# 响应，也一律视为“未提交”，杜绝用伪造响应头冒充成功审计。
SUCCESS_OUTCOMES = frozenset({"success"})


class Outcome(str, enum.Enum):
    """业务结局。值本身会写入审计载荷，不得随意更名。"""

    SUCCESS = "success"
    CLIENT_ERROR = "client_error"
    ERROR = "error"

    @classmethod
    def from_status(cls, status_code: int | None) -> "Outcome":
        if status_code is None:
            return Outcome.ERROR
        if status_code < 400:
            return Outcome.SUCCESS
        if status_code < 500:
            return Outcome.CLIENT_ERROR
        return Outcome.ERROR


def build_dedup_key(request_id: Any) -> str:
    """返回请求级幂等键。"""
    return f"v1:{request_id}"


class AuditEvent:
    """一条可持久化、可去重的审计事件。

    构造时即对载荷做 JSON 兼容化与脱敏（由调用方传入已脱敏的数据），
    本类只负责组织形态与序列化，不做 IO。
    """

    __slots__ = (
        "event_id",
        "dedup_key",
        "seq",
        "occurred_at",
        "request_id",
        "route_name",
        "outcome",
        "status_code",
        "payload",
    )

    def __init__(
        self,
        *,
        request_id: Any,
        outcome: Outcome,
        status_code: int | None,
        route_name: str | None,
        payload: dict[str, Any],
        event_id: str | None = None,
        dedup_key: str | None = None,
        occurred_at: float | None = None,
        seq: int | None = None,
    ) -> None:
        self.event_id = event_id or str(uuid.uuid4())
        self.dedup_key = dedup_key or build_dedup_key(request_id)
        self.seq = seq
        self.occurred_at = (
            occurred_at if occurred_at is not None else time.time()
        )
        self.request_id = str(request_id) if request_id is not None else None
        self.route_name = route_name
        self.outcome = outcome.value
        self.status_code = status_code
        self.payload = payload

    # ------------------------------------------------------------------ #
    # 序列化
    # ------------------------------------------------------------------ #

    def to_envelope(self) -> dict[str, Any]:
        """投递到接收端、写入存储的完整 JSON 结构。"""
        envelope = dict(self.payload)
        envelope.update(
            {
                "schema": SCHEMA_VERSION,
                "event_id": self.event_id,
                "dedup_key": self.dedup_key,
                "occurred_at": self.occurred_at,
                "request_id": self.request_id,
                "route_name": self.route_name,
                "outcome": self.outcome,
                "status_code": self.status_code,
            }
        )
        # seq 由存储层在认领时赋上（首次构造时尚未落库）。
        # 接收端可用它对跨 worker / 重试造成的乱序做稳定排序。
        if self.seq is not None:
            envelope["seq"] = self.seq
        return envelope

    def to_json(self) -> str:
        return json.dumps(
            self.to_envelope(), ensure_ascii=False, separators=(",", ":")
        )

    @classmethod
    def from_row(
        cls,
        *,
        event_id: str,
        dedup_key: str,
        occurred_at: float,
        request_id: str | None,
        route_name: str | None,
        outcome: str,
        status_code: int | None,
        payload_raw: str,
        seq: int | None = None,
    ) -> "AuditEvent":
        payload = json.loads(payload_raw)
        event = cls.__new__(cls)
        event.event_id = event_id
        event.dedup_key = dedup_key
        event.seq = seq
        event.occurred_at = occurred_at
        event.request_id = request_id
        event.route_name = route_name
        event.outcome = outcome
        event.status_code = status_code
        event.payload = payload
        return event

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return (
            f"<AuditEvent {self.event_id} key={self.dedup_key} "
            f"{self.outcome} {self.status_code}>"
        )
