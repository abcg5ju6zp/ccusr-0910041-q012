# Sanic 服务框架

本项目提供异步 HTTP 服务、路由、蓝图、中间件、信号和工作进程管理能力。生产源码位于 `sanic/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install -e . pytest sanic-testing pytest-asyncio`

## 测试

`python3 -m pytest -q tests/test_blueprints.py tests/test_blueprint_group.py`

审计投递箱测试：

`python3 -m pytest -q tests/test_audit_store.py tests/test_audit_integration.py`

## 构建

`python3 -m compileall -q sanic`

## 使用

应用通过 `Sanic` 创建服务，通过蓝图组合路由，并可使用测试客户端完成本地 HTTP 验收。

## 持久审计投递箱（`sanic.audit`）

合规要求关键接口在业务响应完成后留下可追踪审计事件，但请求内直接
调用外部记录器会拖慢响应、进程崩溃又会丢失已承诺事件。`sanic.audit`
提供一个**进程内持久投递箱（transactional outbox）**：事件先落本地
持久存储，再由后台批次投递给外部记录器，并维护确认水位。

### 快速接入

```python
from sanic import Sanic
from sanic.response import json
from sanic.audit import AuditOutbox

async def audit_recorder(events):
    # events 是按 seq 升序的 AuditEvent 列表；需要 JSON 时用
    # event.to_envelope()。正常返回 = 整批确认；
    # 抛 AuditDeliveryError = 整批（或未接受部分）重试。
    await http_client.post("https://auditor.example.com/events",
                           json=[e.to_envelope() for e in events])

app = Sanic("app")
AuditOutbox.attach(
    app,
    audit_recorder,
    db_path="/var/lib/app/audit.db",
    admin_token=os.environ["AUDIT_ADMIN_TOKEN"],  # 管理接口写操作必需
)

@app.post("/orders")
async def create_order(request):
    order = await create_order_tx(...)              # 业务事务
    request.ctx.audit_commit = order.commit_id      # 业务提交标识
    return json({"id": order.id}, status=201)
```

业务提交标识也可通过成功响应头 `X-Audit-Commit` 声明（`request.ctx`
优先）。请求身份（`X-Request-ID` / 生成的 UUID）、路由结果（命中的
路由名、URI、方法）由框架在生命周期信号中自动采集，业务代码无侵入。

### 事件与去重

每条事件包含 `event_id`（单次投递标识）、`dedup_key`（幂等键，
固定 `v1:<request_id>`）、`seq`（库内单调序号）、请求身份、路由
结果、业务结局、状态码、业务提交标识。

* 同一请求无论触发几条采集路径（正常响应、异常兜底、重启补写、
  重复信号），库里只有一行：`dedup_key` 建唯一索引，`INSERT …
  ON CONFLICT DO NOTHING`，并以**先落库者的结局为准**。
* 接收端必须以 `dedup_key` 幂等：崩溃恢复与人工重放后可能重复
  发送，整体是 **at-least-once** 语义。

### 成败判定：业务失败不得伪造成成功审计

结局由框架依据**真实响应状态码 / 异常**判定（`<400` success、
`4xx` client_error、`5xx`/异常/无响应 error）。业务提交标识**仅在
成功结局下采纳**——失败响应即便携带 `X-Audit-Commit` 或设置
`request.ctx.audit_commit` 也一律忽略。

### 投递失败、重试与死信

* 后台 worker 周期性按 `seq` 升序认领一批（`pending → inflight`）。
* 成功：同事务标记 `confirmed` 并推进水位。
* 可重试失败：指数退避（按每行 `attempts`，`not_before` 挡住提前
  认领）；超过 `max_attempts` 转入 `dead` 死信，等待人工处置。
* sink 抛 `AuditDeliveryError(retryable=False)` 表示永久拒绝，
  直接死信；可带 `accepted_keys` 表达批次部分接受。
* 存储彻底不可写时，事件以 JSON Lines 追加到
  `<db>.fallback.jsonl` 并打 `critical` 日志，作为“有事件未入库”
  的兜底证据链，绝不静默丢弃，也绝不把失败记成成功。

### 进程重启与“已承诺不丢”

默认 `durability="before_send"`：事件先在 SQLite(WAL,
`synchronous=NORMAL`) 提交，响应随后才发出——一次本地顺序写，区别
于请求内的网络往返。认领采用**租约**：投递进程崩溃后，租约过期的
`inflight` 事件在下次启动时退回 `pending` 重新认领。`after_send`
模式不阻塞响应但有极小丢失窗口，停机时会等待在途落库任务。

### 乱序与确认水位

投递严格按 `seq` 升序、单批次串行；第 N 条失败不会让第 N+1 条越过
它。水位是“连续 confirmed 的最高 `seq`”，任何 pending/inflight/
dead 都会挡住它，**缺口在管理接口可见而不会被掩盖**；信封内的
`seq` 也可供接收端对跨 worker/重试造成的乱序做稳定排序。

### 脱敏

事件在**入库前**脱敏：嵌套映射中的敏感键（authorization、cookie、
password、token、api_key 等）整体替换为 `[REDACTED]`；请求头采用
白名单（默认仅 content-type/user-agent/x-request-id/accept）；
自由文本（如异常消息）中的 `key=secret` 内联片段按正则清洗；错误
消息截断长度。库中不保存明文凭证。

### 管理接口

默认挂载在 `/_audit`（可改前缀；该前缀自身豁免审计，避免自激）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/stats` | 水位、积压（pending/inflight/dead/confirmed）、最老积压年龄 |
| GET | `/events?status=&limit=&offset=` | 事件列表（默认仅未确认积压） |
| GET | `/events/<seq>` | 单条详情（载荷同样只有脱敏数据） |
| POST | `/events/<seq>/replay` | 安全重放单条**未确认**事件（202） |
| POST | `/replay` | 按状态批量重放（默认仅 `dead`） |
| POST | `/flush` | 立即触发一轮投递并返回最新概况 |

安全策略：

* 写操作（replay/flush）必须携带管理令牌（`Authorization: Bearer
  <token>` 或 `X-Audit-Admin-Token`），比较使用常量时间；**未配置
  令牌时写操作一律 403**，默认安全。
* 只读接口默认仅允许回环地址，或携带有效令牌。
* **已确认事件永不重放**（存储层二次拒绝，返回 403），避免向接收
  端制造重复通知；重放会清零 `attempts` 并回到队首。

### 自定义投递目标

继承 `sanic.audit.AuditSink` 实现 `async def deliver(self, events)`，
或传入任意 `async fn(events)`；内置 `HTTPSink` 使用标准库 POST JSON
批次。需要连接池、mTLS、请求签名的生产环境推荐自定义 sink。
