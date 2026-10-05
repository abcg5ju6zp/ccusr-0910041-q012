"""后台批次投递器。

职责
====

* 周期性地按 ``seq`` 升序认领一批 pending 事件投递给 sink；
* 成功则确认并在同一存储事务内推进确认水位；
* 失败则按指数退避重试（退避值由存储层按每行 attempts 计算），
  超过上限转死信；接收端明确永久拒绝则直接死信；
* 启动时回收上一进程遗留在 inflight、租约已过期的事件；
* 优雅停止：超时尚未完成的批次绝不标记成功，事件留在库中，由
  租约过期机制在下一进程重新认领。

乱序策略
========

投递严格按 ``seq`` 升序，且同一时刻只有一个在飞批次（投递器单任务
串行认领）。若第 N 条长期失败，第 N+1 条不会越过它单独投递——这与
水位“连续确认”的定义一致，缺口暴露在管理接口而不是被悄悄掩盖。
需要跳过坏事件时由管理员显式重放，或等其进入死信。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid

from typing import Any

from sanic.audit.sinks import AuditDeliveryError, AuditSink
from sanic.audit.store import AuditStore


logger = logging.getLogger("sanic.audit.outbox")


class OutboxDeliveryService:
    def __init__(
        self,
        store: AuditStore,
        sink: AuditSink,
        *,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        lease_seconds: float = 60.0,
        max_attempts: int = 8,
        base_backoff: float = 1.0,
        max_backoff: float = 300.0,
        shutdown_grace: float = 25.0,
    ) -> None:
        self._store = store
        self._sink = sink
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._lease_seconds = lease_seconds
        self._max_attempts = max_attempts
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._shutdown_grace = shutdown_grace
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._wakeup = asyncio.Event()
        # 主循环与管理接口的手动 flush 不得并发认领（否则会有两个
        # 在飞批次，破坏单批次顺序假设）。
        self._flush_lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._wakeup.clear()
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        if self._task is None:
            await self._sink.close()
            return
        self._stop.set()
        self._wakeup.set()
        try:
            await asyncio.wait_for(self._task, timeout=self._shutdown_grace)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # 超时也绝不强标成功：未确认事件仍带租约留在库中，
            # 下一进程租约过期后重新认领。
            self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task
        finally:
            self._task = None
        await self._sink.close()

    def kick(self) -> None:
        """请求尽快再跑一轮（新事件落库后调用，降低投递延迟）。"""
        self._wakeup.set()

    # ------------------------------------------------------------------ #
    # 主循环
    # ------------------------------------------------------------------ #

    async def _run(self) -> None:
        try:
            reclaimed = await self._store.reclaim_stale(self._lease_seconds)
            if reclaimed:
                logger.warning(
                    "audit outbox recovered %d inflight event(s) from a"
                    " previous process",
                    reclaimed,
                )
        except Exception:
            logger.exception("audit outbox stale reclaim failed")

        while not self._stop.is_set():
            self._wakeup.clear()
            try:
                worked = await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("audit outbox flush iteration failed")
                worked = False

            if worked and not self._stop.is_set():
                # 有活干立刻再来一轮，尽快清空积压。
                self.kick()
                continue
            try:
                await asyncio.wait_for(
                    self._wakeup.wait(), timeout=self._flush_interval
                )
            except asyncio.TimeoutError:
                pass

    async def flush_once(self) -> bool:
        """执行单轮认领与投递，返回是否处理了一批。"""
        if self._flush_lock.locked():
            # 另一轮正在投递：不重复认领，让调用方当本轮无活即可。
            return False
        async with self._flush_lock:
            batch_id = uuid.uuid4().hex
            claimed = await self._store.claim_batch(
                self._batch_size,
                lease_seconds=self._lease_seconds,
                batch_id=batch_id,
            )
            if not claimed:
                return False
            seqs = [seq for seq, _ in claimed]
            events = [event for _, event in claimed]
            await self._deliver_batch(seqs, events)
            return True

    async def _deliver_batch(self, seqs: list[int], events: list[Any]) -> None:
        try:
            await self._sink.deliver(events)
        except AuditDeliveryError as exc:
            await self._handle_failure(seqs, events, exc)
        except Exception as exc:  # noqa: BLE001 - sink 契约外异常
            logger.exception("audit sink raised an unexpected error")
            await self._handle_failure(
                seqs, events, AuditDeliveryError(str(exc))
            )
        else:
            watermark = await self._store.mark_confirmed(seqs)
            logger.debug(
                "audit batch confirmed: %d event(s), watermark=%d",
                len(events),
                watermark,
            )

    async def _handle_failure(
        self,
        seqs: list[int],
        events: list[Any],
        exc: AuditDeliveryError,
    ) -> None:
        seq_by_key = {event.dedup_key: seq for seq, event in zip(seqs, events)}
        accepted = {
            seq_by_key[key] for key in exc.accepted_keys if key in seq_by_key
        }
        failed = [seq for seq in seqs if seq not in accepted]

        if accepted:
            # 部分成功：只确认接收端已接受的事件，其余正常处理。
            await self._store.mark_confirmed(sorted(accepted))

        if not failed:
            return

        errors = {seq: str(exc)[:1000] for seq in failed}

        if not exc.retryable:
            # 接收端明确表示负载永远不会被接受（如鉴权/格式 4xx）：
            # 直接死信，避免无意义重试；事件中的业务结局仍如实保留。
            await self._store.mark_dead(failed, str(exc)[:1000])
            logger.error(
                "audit batch permanently rejected: %d event(s) moved to"
                " dead-letter: %s",
                len(failed),
                exc,
            )
            return

        retried, dead = await self._store.mark_retry(
            failed,
            errors,
            base_backoff=self._base_backoff,
            max_backoff=self._max_backoff,
            max_attempts=self._max_attempts,
        )
        logger.warning(
            "audit delivery failed: %s | retry=%d dead=%d",
            exc,
            retried,
            dead,
        )
        if dead:
            logger.error(
                "audit event(s) exhausted %d attempts and moved to"
                " dead-letter (seqs=%s)",
                self._max_attempts,
                failed[-dead:],
            )
        # 退避由 not_before 实现：退避期间主循环空转，不会提前认领。
