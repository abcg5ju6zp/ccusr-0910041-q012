"""审计载荷脱敏。

审计事件落盘（SQLite）并离开信任边界投递到外部记录器，因此载荷在
*进入投递箱之前* 就必须脱敏，而不是只在展示时处理。

规则：

* :data:`DEFAULT_SENSITIVE_FIELDS` 中的字段名（大小写不敏感）一律替换
  为 :data:`REDACTED`。
* 支持嵌套 dict / list，默认深度受限，防止异常深结构造成的资源消耗。
* 白名单字段（如 ``request_id``、``route`` 等非敏感标识）即使名字
  命中也保留——通过调用方只传入安全字段保证，这里不做特殊放行。
"""

from __future__ import annotations

import enum
import re

from typing import Any


REDACTED = "[REDACTED]"

#: 形如 ``password=abc`` / ``token: xyz`` 的内联凭证片段（异常消息、
#: 自由文本字段常见）。值在空白或常见分隔符处结束。
_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|access_token|refresh_token"
    r"|api[_-]?key|authorization|cookie|sessionid?)"
    r"(\s*[:=]\s*)([^\s,;&\"']+)"
)


def scrub_text(text: str) -> str:
    """清洗自由文本中的 ``key=secret`` 内联片段。"""
    if not isinstance(text, str):
        return text
    return _INLINE_SECRET_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text
    )


DEFAULT_SENSITIVE_FIELDS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "x-api-key",
        "session",
        "sessionid",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
    }
)

# HTTP 头在框架内是大小写不敏感的，统一按小写比较。
_SENSITIVE_LOWER = frozenset(name.lower() for name in DEFAULT_SENSITIVE_FIELDS)

_MAX_DEPTH = 8


def _is_sensitive(name: str) -> bool:
    return name.lower() in _SENSITIVE_LOWER


def redact_value(
    value: Any,
    *,
    depth: int = 0,
) -> Any:
    """递归脱敏容器；标量原样返回。"""
    if depth >= _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED
                if _is_sensitive(str(key))
                else redact_value(val, depth=depth + 1)
            )
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_value(item, depth=depth + 1) for item in value]
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, str):
        # 字符串内部也可能含 key=secret 片段（如异常消息）。
        return scrub_text(value)
    return value


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """脱敏一个顶层映射，返回新 dict。"""
    return {
        str(key): (
            REDACTED
            if _is_sensitive(str(key))
            else redact_value(value, depth=1)
        )
        for key, value in data.items()
    }


def safe_headers(
    headers,
    *,
    allow: frozenset[str] | None = None,
) -> dict[str, str]:
    """从 HTTP 头中提取允许外发的字段，其余全部丢弃。

    采用白名单而非黑名单：头种类繁多且可能含自定义凭证，只放行
    审计需要的少量标识头。``allow`` 内的名称大小写不敏感。
    """
    allowed = allow or frozenset()
    wanted = {name.lower() for name in allowed}
    result: dict[str, str] = {}
    if not headers:
        return result
    for name in wanted:
        try:
            value = headers.getone(name)
        except Exception:
            # 缺头或不同 Header 实现：跳过该头即可。
            continue  # nosec B112
        if value is not None:
            # 白名单头仍然过一遍黑名单，防止有人把 token 塞进允许集。
            result[name] = REDACTED if _is_sensitive(name) else _scalar(value)
    return result


def _scalar(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, (dict, list, tuple)):
        return redact_value(value, depth=1)
    return value
