# 合同文本脱敏 API

基于 FastAPI 的合同文本脱敏服务：客户端提交原文与敏感片段（起止位置、优先级、类别），服务按**原始 Unicode 位置一次性解析重叠片段**，生成稳定占位符，并将「占位符 → 原文」映射**加密**保存（可设置过期时间）。查询接口返回脱敏文本与片段明细；恢复接口**仅凭一次性令牌**还原指定占位符。

## 快速启动（单命令）

```bash
docker compose up --build
```

服务监听 `http://localhost:8000`，交互式文档见 `http://localhost:8000/docs`。

生产部署请显式指定主密钥：

```bash
REDACTION_MASTER_KEY="$(openssl rand -base64 32)" docker compose up --build
```

### 本地开发（不用 Docker）

```bash
pip install -r requirements-dev.txt
python scripts/init_db.py        # 初始化 SQLite（幂等，服务启动时也会自动执行）
uvicorn app.main:app --reload    # http://127.0.0.1:8000
pytest                           # 运行测试
```

## API 使用示例

### 1. 提交脱敏任务 `POST /v1/redactions`

位置为**原文的 Unicode 码点偏移**（与 Python 字符串索引一致，`start` 含、`end` 不含）。

```bash
curl -s -X POST http://localhost:8000/v1/redactions \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "甲方张三（身份证号110101199001011234）与乙方北京示例科技有限公司签订合同",
    "fragments": [
      {"start": 2,  "end": 4,  "category": "name",      "priority": 5},
      {"start": 9,  "end": 27, "category": "id_number", "priority": 10},
      {"start": 24, "end": 30, "category": "id_tail",   "priority": 1},
      {"start": 31, "end": 41, "category": "company",   "priority": 5}
    ],
    "mapping_ttl_seconds": 604800,
    "token_ttl_seconds": 86400
  }'
```

响应（`201`）：

```json
{
  "document_id": "doc_7f3a…",
  "redacted_text": "甲方[[NAME#…]]（身份证号[[ID_NUMBER#…]]）与乙方[[COMPANY#…]]签订合同",
  "fragments": [
    {"placeholder": "[[NAME#…]]", "category": "NAME", "start": 2, "end": 4,
     "redacted_start": 2, "redacted_end": 16, "priority": 5,
     "expires_at": "2026-09-28T…", "expired": false}
  ],
  "dropped": [
    {"start": 24, "end": 30, "category": "ID_TAIL", "priority": 1,
     "reason": "overlap_higher_priority"}
  ],
  "restore_token": "仅在此次响应中出现的一次性令牌",
  "restore_token_expires_at": "2026-09-22T…"
}
```

上例中 `id_tail [24,30)` 与优先级更高的 `id_number [9,27)` 重叠，被丢弃并记入 `dropped`。

### 2. 查询脱敏结果 `GET /v1/redactions/{document_id}`

```bash
curl -s http://localhost:8000/v1/redactions/doc_7f3a…
```

返回脱敏文本与全部片段明细（占位符、类别、原文/脱敏后位置、过期状态），**不含任何明文**。

### 3. 恢复指定占位符 `POST /v1/redactions/{document_id}/restore`

```bash
curl -s -X POST http://localhost:8000/v1/redactions/doc_7f3a…/restore \
  -H 'Content-Type: application/json' \
  -d '{"token": "<restore_token>", "placeholders": ["[[NAME#…]]"]}'
```

返回 `restored_text`（仅指定占位符被还原，其余保持脱敏）及还原明细。令牌**用后即焚**：

| 情形 | 状态码 |
|---|---|
| 令牌错误 | `401` |
| 令牌已使用 | `409` |
| 令牌已过期 | `410` |
| 占位符不存在 | `404`（不消耗令牌） |
| 映射已过期 | `410`（不消耗令牌） |

## 设计说明

- **重叠解析**：按 `(优先级降序, 起始位置升序, 跨度降序)` 排序后贪心选取互不重叠的片段；再按起始位置对**原文**做单次从左到右扫描生成脱敏文本，所有偏移始终指向原始文档，不会因替换而移位。
- **稳定占位符**：格式 `[[类别#摘要]]`，摘要为 `HMAC-SHA256(文档ID:起:止:类别)` 的前 12 位十六进制——同一文档内同一片段恒得同一占位符，且无法被伪造碰撞。
- **加密映射**：片段明文使用 Fernet（AES-128-CBC + HMAC）加密后存入 SQLite；主密钥来自环境变量 `REDACTION_MASTER_KEY`（任意口令将经 PBKDF2 派生，也可直接给 44 字符 Fernet 密钥）。未设置时服务会生成密钥并持久化到 `DATA_DIR/.master_key`（仅限开发）。
- **过期机制**：映射与令牌均带 `expires_at`；过期映射不可恢复，过期令牌不可用。
- **一次性令牌**：创建任务时签发，库中只存 SHA-256 摘要；恢复时通过单条原子 `UPDATE ... WHERE used_at IS NULL` 消费，杜绝并发重复使用。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DATA_DIR` | `./data`（容器内 `/data`） | 数据目录 |
| `DATABASE_PATH` | `$DATA_DIR/redaction.db` | SQLite 文件路径 |
| `REDACTION_MASTER_KEY` | 无（自动生成并落盘） | 主密钥 / 口令 |
| `REDACTION_KEY_FILE` | `$DATA_DIR/.master_key` | 自动密钥的保存位置 |
| `TOKEN_TTL_SECONDS` | `86400` | 一次性令牌默认有效期 |
| `MAPPING_TTL_SECONDS` | 无（永不过期） | 映射默认有效期，可被请求级 `mapping_ttl_seconds` 覆盖 |

## 项目结构

```
app/
  main.py       # FastAPI 路由与事务编排
  redact.py     # 重叠解析 + 单遍脱敏引擎（纯函数）
  security.py   # Fernet 加解密、占位符摘要、一次性令牌
  db.py         # SQLite 连接与建表（WAL）
  config.py     # 环境变量配置
  schemas.py    # Pydantic 请求/响应模型
scripts/init_db.py   # SQLite 初始化脚本（幂等）
tests/               # pytest：引擎单测 + API 端到端
Dockerfile / docker-compose.yml
```
