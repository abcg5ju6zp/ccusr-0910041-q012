"""持久审计投递箱（audit outbox）。

公开 API::

    from sanic.audit import AuditOutbox, AuditSink, FunctionSink

    async def record(events):
        ...  # 投递到外部记录器；正常返回=确认，抛 AuditDeliveryError=重试

    AuditOutbox.attach(app, record, db_path="/var/lib/app/audit.db",
                       admin_token=os.environ["AUDIT_ADMIN_TOKEN"])

业务侧在成功响应中带上提交标识（``X-Audit-Commit`` 或
``request.ctx.audit_commit``）即可，其余由框架采集。
"""

from sanic.audit.delivery import OutboxDeliveryService
from sanic.audit.events import AuditEvent, Outcome
from sanic.audit.outbox import (
    DEFAULT_COMMIT_HEADER,
    AuditOptions,
    AuditOutbox,
)
from sanic.audit.redaction import REDACTED
from sanic.audit.sinks import (
    AuditDeliveryError,
    AuditSink,
    FunctionSink,
    HTTPSink,
)
from sanic.audit.store import AlreadyConfirmed, AuditStore


__all__ = [
    "AuditOutbox",
    "AuditOptions",
    "AuditEvent",
    "Outcome",
    "AuditStore",
    "OutboxDeliveryService",
    "AuditSink",
    "FunctionSink",
    "HTTPSink",
    "AuditDeliveryError",
    "AlreadyConfirmed",
    "DEFAULT_COMMIT_HEADER",
    "REDACTED",
]
