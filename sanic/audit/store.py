"""投递箱持久化存储（SQLite / WAL）。

设计要点
========

* 所有写入都是独立事务，默认 ``synchronous=NORMAL`` + WAL：一次请求
  返回前的落库只多一次顺序写；进程崩溃 / 断电后已提交事件不丢失。
* ``seq`` 单调递增，是“乱序”问题的总序依据：认领按 ``seq`` 升序，
  水位按 ``seq`` 连续推进。
* ``dedup_key`` 唯一索引保证同一请求（含信号重复触发、重启补写）
  在库里只有一行。
* ``inflight`` 带租约（``leased_until``）：投递进程崩溃后，租约
  过期的事件会被重新认领；接收端再以 ``dedup_key`` 做最终幂等。
* 所有 sqlite 调用都在单线程 executor 中执行，连接不跨线程共享，
  天然串行化，不阻塞事件循环。
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable, Sequence

from sanic.audit.events import AuditEvent, Outcome


# 状态机：pending -> inflight -> confirmed
#                      \-> pending (重试，指数退避)
#                      \-> dead    (超过最大尝试，等待人工重放)
STATUS_PENDING = "pending"
STATUS_INFLIGHT = "inflight"
STATUS_CONFIRMED = "confirmed"
STATUS_DEAD = "dead"
TERMINAL_STATUSES = frozenset({STATUS_CONFIRMED, STATUS_DEAD})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_outbox (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    dedup_key    TEXT NOT NULL UNIQUE,
    occurred_at  REAL NOT NULL,
    request_id   TEXT,
    route_name   TEXT,
    outcome      TEXT NOT NULL,
    status_code  INTEGER,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    not_before   REAL NOT NULL DEFAULT 0,
    leased_until REAL NOT NULL DEFAULT 0,
    batch_id     TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_status
    ON audit_outbox(status, seq);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_notbefore
    ON audit_outbox(status, not_before);

CREATE TABLE IF NOT EXISTS audit_cursor (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    watermark_seq   INTEGER NOT NULL DEFAULT 0,
    updated_at      REAL NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO audit_cursor (id, watermark_seq) VALUES (1, 0);
"""


class EnqueueResult:
    """落库结果。``inserted=False`` 表示命中去重（重复事件）。"""

    __slots__ = ("inserted", "seq", "duplicate_of")

    def __init__(self, inserted: bool, seq: int, duplicate_of: int | None):
        self.inserted = inserted
        self.seq = seq
        self.duplicate_of = duplicate_of

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<EnqueueResult inserted={self.inserted} seq={self.seq}"
            + (f" dup_of={self.duplicate_of}" if self.duplicate_of else "")
            + ">"
        )


class AuditStore:
    """异步门面：所有方法把同步 sqlite 操作派发到专用线程。"""

    def __init__(self, path: str) -> None:
        self._path = path
        self._executor: ThreadPoolExecutor | None = None
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        return await self._submit(self._connect)

    async def close(self) -> None:
        def _close() -> None:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

        if self._executor is not None:
            await self._submit(_close)
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._executor = None

    async def __aenter__(self) -> "AuditStore":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _connect(self) -> None:
        conn = sqlite3.connect(
            self._path,
            check_same_thread=False,
            isolation_level=None,  # 自动提交模式；事务用 BEGIN/COMMIT 显式控制
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        self._conn = conn

    async def _submit(self, fn, *args):
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="audit-outbox"
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, lambda: fn(*args))

    # ------------------------------------------------------------------ #
    # 写入：去重落库
    # ------------------------------------------------------------------ #

    async def enqueue(self, event: AuditEvent) -> EnqueueResult:
        return await self._submit(self._enqueue, event)

    def _enqueue(self, event: AuditEvent) -> EnqueueResult:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        now = time.time()
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                """
                INSERT INTO audit_outbox (
                    event_id, dedup_key, occurred_at, request_id,
                    route_name, outcome, status_code, payload, status,
                    attempts, created_at, updated_at, not_before
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)
                ON CONFLICT(dedup_key) DO NOTHING
                """,
                (
                    event.event_id,
                    event.dedup_key,
                    event.occurred_at,
                    event.request_id,
                    event.route_name,
                    event.outcome,
                    event.status_code,
                    event.to_json(),
                    STATUS_PENDING,
                    now,
                    now,
                ),
            )
            if cur.rowcount == 1:
                seq = cur.lastrowid
                if seq is None:  # 成功 INSERT 后 SQLite 必给 rowid
                    raise RuntimeError("sqlite did not return rowid")
                conn.execute("COMMIT")
                return EnqueueResult(True, seq, None)

            # 命中唯一约束：读回已存在的行，首写意志不变。
            row = conn.execute(
                "SELECT seq, status FROM audit_outbox WHERE dedup_key = ?",
                (event.dedup_key,),
            ).fetchone()
            conn.execute("COMMIT")
            return EnqueueResult(False, row["seq"], row["seq"])
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    # 认领 / 确认 / 失败：后台批次投递的事务边界
    # ------------------------------------------------------------------ #

    async def reclaim_stale(self, lease_seconds: float) -> int:
        """把租约过期的 inflight 事件退回 pending（崩溃恢复）。"""
        return await self._submit(self._reclaim_stale, lease_seconds)

    def _reclaim_stale(self, lease_seconds: float) -> int:
        # lease_seconds 仅作为调用方语义参数留痕；判定以租约到期时刻
        # 为准：leased_until 是认领时设定的绝对到期时间。
        del lease_seconds
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        now = time.time()
        cur = self._conn.execute(
            "UPDATE audit_outbox SET status = ?, leased_until = 0,"
            " updated_at = ? WHERE status = ? AND leased_until > 0"
            " AND leased_until < ?",
            (STATUS_PENDING, now, STATUS_INFLIGHT, now),
        )
        return cur.rowcount

    async def claim_batch(
        self,
        limit: int,
        *,
        lease_seconds: float,
        batch_id: str,
    ) -> list[tuple[int, AuditEvent]]:
        return await self._submit(
            self._claim_batch, limit, lease_seconds, batch_id
        )

    def _claim_batch(
        self,
        limit: int,
        lease_seconds: float,
        batch_id: str,
    ) -> list[tuple[int, AuditEvent]]:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        conn = self._conn
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT seq FROM audit_outbox"
                " WHERE status = ? AND not_before <= ?"
                " ORDER BY seq ASC LIMIT ?",
                (STATUS_PENDING, now, limit),
            ).fetchall()
            seqs = [row["seq"] for row in rows]
            if seqs:
                # 仅拼接等量 "?" 占位符；seq 为库内整数且全部参数绑定。
                placeholders = ",".join("?" for _ in seqs)
                # 只拼接 "?" 占位符：seq 为库内整数，值全部参数绑定。
                conn.execute(
                    f"UPDATE audit_outbox SET status = ?, attempts ="  # nosec B608
                    f" attempts + 1, leased_until = ?, batch_id = ?,"
                    f" updated_at = ? WHERE seq IN ({placeholders})",
                    [
                        STATUS_INFLIGHT,
                        now + lease_seconds,
                        batch_id,
                        now,
                        *seqs,
                    ],
                )
                fetched = conn.execute(
                    f"SELECT * FROM audit_outbox WHERE seq IN"  # nosec B608
                    f" ({placeholders}) ORDER BY seq ASC",
                    seqs,
                ).fetchall()
            else:
                fetched = []
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return [(row["seq"], self._row_to_event(row)) for row in fetched]

    async def mark_confirmed(
        self,
        seqs: Iterable[int],
        *,
        ack: str | None = None,
    ) -> int:
        """确认投递成功并推进水位，返回新的水位 seq。"""
        return await self._submit(self._mark_confirmed, list(seqs), ack)

    def _mark_confirmed(self, seqs: list[int], ack: str | None) -> int:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        if not seqs:
            return self._watermark()
        conn = self._conn
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "UPDATE audit_outbox SET status = ?, last_error = NULL,"
                " leased_until = 0, updated_at = ? WHERE seq = ?"
                " AND status = ?",
                [
                    (STATUS_CONFIRMED, now, seq, STATUS_INFLIGHT)
                    for seq in seqs
                ],
            )
            watermark = self._advance_watermark(conn, now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return watermark

    def _advance_watermark(self, conn: sqlite3.Connection, now: float) -> int:
        """水位 = 从当前位置起连续 confirmed 的最高 seq。

        dead/pending/inflight 都会挡住水位，缺口因此在管理接口可见，
        不会被后面的成功事件“跳过”掩盖。
        """
        row = conn.execute(
            "SELECT watermark_seq FROM audit_cursor WHERE id = 1"
        ).fetchone()
        watermark = row["watermark_seq"]
        while True:
            nxt = conn.execute(
                "SELECT status FROM audit_outbox WHERE seq = ?",
                (watermark + 1,),
            ).fetchone()
            if nxt is None or nxt["status"] != STATUS_CONFIRMED:
                break
            watermark += 1
        conn.execute(
            "UPDATE audit_cursor SET watermark_seq = ?, updated_at = ?"
            " WHERE id = 1",
            (watermark, now),
        )
        return watermark

    async def mark_retry(
        self,
        seqs: Sequence[int],
        errors: dict[int, str],
        *,
        base_backoff: float,
        max_backoff: float,
        max_attempts: int,
    ) -> tuple[int, int]:
        """投递失败：按各行自身 attempts 指数退避，超限转死信。

        退避在存储层按行计算（单 worker 无惊群，不需要抖动）：
        ``delay = min(max_backoff, base_backoff * 2 ** (attempts-1))``。
        返回 (重试数, 死信数)。
        """
        return await self._submit(
            self._mark_retry,
            list(seqs),
            dict(errors),
            base_backoff,
            max_backoff,
            max_attempts,
        )

    def _mark_retry(
        self,
        seqs: list[int],
        errors: dict[int, str],
        base_backoff: float,
        max_backoff: float,
        max_attempts: int,
    ) -> tuple[int, int]:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        now = time.time()
        retried = dead = 0
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            for seq in seqs:
                row = conn.execute(
                    "SELECT attempts FROM audit_outbox WHERE seq = ?",
                    (seq,),
                ).fetchone()
                if row is None:
                    continue
                error = errors.get(seq, "delivery failed")
                if row["attempts"] >= max_attempts:
                    conn.execute(
                        "UPDATE audit_outbox SET status = ?,"
                        " leased_until = 0, last_error = ?,"
                        " updated_at = ? WHERE seq = ?",
                        (STATUS_DEAD, error[:1000], now, seq),
                    )
                    dead += 1
                else:
                    delay = min(
                        max_backoff,
                        base_backoff * 2 ** (row["attempts"] - 1),
                    )
                    conn.execute(
                        "UPDATE audit_outbox SET status = ?,"
                        " leased_until = 0, last_error = ?,"
                        " not_before = ?, updated_at = ? WHERE seq = ?",
                        (
                            STATUS_PENDING,
                            error[:1000],
                            now + delay,
                            now,
                            seq,
                        ),
                    )
                    retried += 1
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return retried, dead

    async def mark_dead(self, seqs: Sequence[int], reason: str) -> int:
        """接收端永久拒绝（不可重试）时直接转入死信。"""
        return await self._submit(self._mark_dead, list(seqs), reason)

    def _mark_dead(self, seqs: list[int], reason: str) -> int:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        if not seqs:
            return 0
        now = time.time()
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "UPDATE audit_outbox SET status = ?, leased_until = 0,"
                " last_error = ?, updated_at = ? WHERE seq = ?"
                " AND status = ?",
                [
                    (STATUS_DEAD, reason[:1000], now, seq, STATUS_INFLIGHT)
                    for seq in seqs
                ],
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return len(seqs)

    # ------------------------------------------------------------------ #
    # 管理接口：积压查询与安全重放
    # ------------------------------------------------------------------ #

    async def stats(self) -> dict[str, Any]:
        return await self._submit(self._stats)

    def _stats(self) -> dict[str, Any]:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        now = time.time()
        counts = {
            STATUS_PENDING: 0,
            STATUS_INFLIGHT: 0,
            STATUS_CONFIRMED: 0,
            STATUS_DEAD: 0,
        }
        for row in self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM audit_outbox GROUP BY status"
        ):
            counts[row["status"]] = row["n"]
        row = self._conn.execute(
            "SELECT watermark_seq, updated_at FROM audit_cursor WHERE id=1"
        ).fetchone()
        oldest = self._conn.execute(
            "SELECT MIN(created_at) AS t FROM audit_outbox"
            " WHERE status IN (?, ?, ?)",
            (STATUS_PENDING, STATUS_INFLIGHT, STATUS_DEAD),
        ).fetchone()
        maxseq = self._conn.execute(
            "SELECT MAX(seq) AS m FROM audit_outbox"
        ).fetchone()["m"]
        return {
            "watermark_seq": row["watermark_seq"],
            "watermark_updated_at": row["updated_at"],
            "max_seq": maxseq or 0,
            "lag": (maxseq or 0) - row["watermark_seq"],
            "pending": counts[STATUS_PENDING],
            "inflight": counts[STATUS_INFLIGHT],
            "confirmed": counts[STATUS_CONFIRMED],
            "dead": counts[STATUS_DEAD],
            "oldest_backlog_age": (
                round(now - oldest["t"], 3) if oldest and oldest["t"] else None
            ),
        }

    async def list_backlog(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return await self._submit(self._list_backlog, status, limit, offset)

    def _list_backlog(
        self, status: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        limit = max(1, min(limit, 500))
        if status is not None and status not in (
            STATUS_PENDING,
            STATUS_INFLIGHT,
            STATUS_DEAD,
            STATUS_CONFIRMED,
        ):
            raise ValueError(f"unknown status: {status}")
        sql = (
            "SELECT seq, event_id, dedup_key, occurred_at, request_id,"
            " route_name, outcome, status_code, status, attempts,"
            " last_error, not_before, leased_until, created_at"
            " FROM audit_outbox"
        )
        params: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        else:
            sql += " WHERE status IN ('pending','inflight','dead')"
        sql += " ORDER BY seq ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(row) for row in self._conn.execute(sql, params)]

    async def get_event(self, seq: int) -> dict[str, Any] | None:
        return await self._submit(self._get_event, seq)

    def _get_event(self, seq: int) -> dict[str, Any] | None:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        row = self._conn.execute(
            "SELECT * FROM audit_outbox WHERE seq = ?", (seq,)
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        # 管理接口也不返回脱敏前数据——payload 本就只存脱敏后的。
        data["payload"] = json.loads(row["payload"])
        return data

    async def replay(
        self,
        *,
        seq: int | None = None,
        statuses: Sequence[str] = (STATUS_DEAD,),
    ) -> list[int]:
        """把指定（或指定状态的）未确认事件重置为 pending。

        已确认事件永不参与重放：即便指定 seq 命中 confirmed 也拒绝，
        防止向接收端重复通知。返回实际重置的 seq 列表。
        """
        return await self._submit(self._replay, seq, tuple(statuses))

    def _replay(
        self,
        seq: int | None,
        statuses: tuple[str, ...],
    ) -> list[int]:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        allowed = {
            STATUS_PENDING,
            STATUS_INFLIGHT,
            STATUS_DEAD,
        }
        statuses = tuple(s for s in statuses if s in allowed)
        if not statuses:
            raise ValueError(
                "replay requires at least one non-terminal status"
            )
        conn = self._conn
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if seq is not None:
                row = conn.execute(
                    "SELECT status FROM audit_outbox WHERE seq = ?",
                    (seq,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise LookupError(seq)
                if row["status"] == STATUS_CONFIRMED:
                    conn.execute("ROLLBACK")
                    raise AlreadyConfirmed(seq)
                seqs = [seq]
                conn.execute(
                    "UPDATE audit_outbox SET status = ?, attempts = 0,"
                    " last_error = NULL, not_before = 0, leased_until = 0,"
                    " batch_id = NULL, updated_at = ? WHERE seq = ?",
                    (STATUS_PENDING, now, seq),
                )
            else:
                # statuses 已在上方白名单过滤，仅拼占位符、值参数绑定。
                placeholders = ",".join("?" for _ in statuses)
                rows = conn.execute(
                    f"SELECT seq FROM audit_outbox WHERE status IN"  # nosec B608
                    f" ({placeholders}) ORDER BY seq ASC",
                    statuses,
                ).fetchall()
                seqs = [r["seq"] for r in rows]
                if seqs:
                    marks = ",".join("?" for _ in seqs)
                    conn.execute(
                        f"UPDATE audit_outbox SET status = ?,"  # nosec B608
                        f" attempts = 0, last_error = NULL, not_before = 0,"
                        f" leased_until = 0, batch_id = NULL,"
                        f" updated_at = ? WHERE seq IN ({marks})",
                        [STATUS_PENDING, now, *seqs],
                    )
            conn.execute("COMMIT")
        except BaseException:
            if self._conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return seqs

    async def prune_confirmed(self, keep_seconds: float) -> int:
        """删除已确认且早于保留期的行，水位不受影响（独立游标）。"""
        return await self._submit(self._prune_confirmed, keep_seconds)

    def _prune_confirmed(self, keep_seconds: float) -> int:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        cur = self._conn.execute(
            "DELETE FROM audit_outbox WHERE status = ? AND updated_at < ?",
            (STATUS_CONFIRMED, time.time() - keep_seconds),
        )
        return cur.rowcount

    async def watermark(self) -> int:
        return await self._submit(self._watermark)

    def _watermark(self) -> int:
        if self._conn is None:
            raise RuntimeError("AuditStore used before start()")
        row = self._conn.execute(
            "SELECT watermark_seq FROM audit_cursor WHERE id = 1"
        ).fetchone()
        return row["watermark_seq"]

    # ------------------------------------------------------------------ #

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> AuditEvent:
        return AuditEvent.from_row(
            event_id=row["event_id"],
            dedup_key=row["dedup_key"],
            occurred_at=row["occurred_at"],
            request_id=row["request_id"],
            route_name=row["route_name"],
            outcome=row["outcome"],
            status_code=row["status_code"],
            payload_raw=row["payload"],
            seq=row["seq"],
        )


class AlreadyConfirmed(Exception):
    """尝试重放已确认事件——安全策略明确拒绝。"""

    def __init__(self, seq: int) -> None:
        super().__init__(
            f"audit event seq={seq} is already confirmed and cannot be"
            " replayed"
        )
        self.seq = seq


__all__ = ["AuditStore", "EnqueueResult", "AlreadyConfirmed", "Outcome"]
