# mhszed-sql

全链路 Web 安全测试平台（SQL 注入方向）：接口采集 → 接口归一 / 会话链路建模 → WAF 画像 →
AI 分级研判（人在回路）→ 流水线探测（SQLMap + AI Payload）→ 漏洞分析 → 证据归档 →
加固报告。前后端分离，深色主题。

> ⚠️ **仅用于已获得明确授权的目标**。使用者需自行确保测试范围合法；
> 因滥用产生的一切后果由使用者本人承担，与作者无关。

## 功能

- 静态爬虫 + Burp 流量推送 + 手动接口录入（三种采集方式）
- 接口归一、参数抽取、业务链还原
- WAF 指纹画像与绕过建议
- AI 分级研判（OpenAI 兼容接口，可无 key 降级为规则引擎）+ 人工复核
- SQLMap 初筛 + AI Payload 精细化探测（限速 / 熔断 / 审计）
- 人工确认 Payload、接口级定向重扫
- 漏洞证据链、报告导出（PDF）
- 知识库（成功 Payload / 误报样本 / 文章知识点）
- 审计日志（哈希链）与日志清空
- **HTTPS 目标协议跟随**：接口采集时记录 scheme，研判/探测/深挖不再硬编码 http
- **盲注自动发现**：布尔确认后做全量反证；扫描阶段出现“疑似可注”信号自动补
  `--technique=T` 定向重试，避免 medium 强度漏掉纯时间盲注
- **盲注深挖回退**：轻量提取失败后自动回退 sqlmap 取当前库名；`dump` 模式继续
  枚举表/脱裤（≤5 行），各步独立预算
- **证据链可复现**：记录 sqlmap `-v 3` 下真实取数 `[PAYLOAD]`、取数语句与命令，
  与检测 Payload 分开标注
- **复核恢复与漏扫修复**：确认后可恢复（review/done/terminated）；按引擎判定是否
  扫完；停止任务/启动时清理僵尸 job；重复扫描只合并证据不重复建漏洞
- **跨进程 host 锁**：后端与独立脚本同时对同一目标跑 sqlmap 时串行排队

## 新功能与使用方式（2026-11）

### 1. HTTPS 目标
直接填 `https://...` 即可。采集、研判、扫描、深挖都会跟随目标协议，无需额外配置。

### 2. 盲注自动发现
无需操作。扫描阶段如果 sqlmap 报告“疑似可注但未确认”，工具会自动对该参数补一次
时间盲注重试；扫出后漏洞类型显示为「时间盲注」。

### 3. 人工复核后恢复扫描
「接口采集 → 复核」里点「确认扫描」；复核队列清空后自动恢复探测。
任务状态是 `done` / `terminated` 也能恢复；重复扫描不会重复建漏洞。

### 4. 盲注深入利用怎么点
「漏洞结果」→ 该漏洞的「深入利用」：

1. 选**模式**：`enum`（库表）/ `dump`（脱裤，最多 5 行）/ `ai`；
2. 选**目标**：`schema`（拿到库名即停）/ `flag`（靶场取 flag）；
3. 盲注目标可勾选**「盲注定向提取」**：
   - 读接口：轻量提取失败后会自动回退 sqlmap，不勾也能跑；
   - 写接口：必须勾选才回退（防止时间盲注真的执行写语句）；
4. 预算：库名 300s、表枚举 600s、脱裤 300s；超时会保留已完成部分。

> 纯时间盲注的表枚举/脱裤天然很慢，可能超时；能取到库名即已证明可读库。

### 5. 证据链怎么看
「漏洞结果」→「证据链」：

- 摘要按**「结果 → 对应 payload/命令」**排列：
  `数据库名 → 取数 Payload → sqlmap 参数`；表和样本同理；
- 「取数 Payload」是 sqlmap 真实发出的取数语句（`-v 3` 的 `[PAYLOAD]`），可直接复现；
- 「检测 Payload（非取数语句）」放在最后，只用于确认注入点；
- 深挖过程在「过程记录」折叠中；抽屉打开时每 5 秒自动刷新。

### 6. 这些不用手动管
重复漏洞合并、僵尸 job 清理、任务恢复、同一 host 的 sqlmap 排队，工具会自动处理。
正常从 UI 使用不会出现并发互抢；不要在后端运行时另起脚本打同一目标即可。

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.10+ · FastAPI · SQLAlchemy · SQLite |
| 前端 | Vue 3 · Element Plus · Vite |
| 检测 | 内置 SQLMap（`tools/sqlmap`，GPLv2） |

## 目录结构

```
backend/            FastAPI 后端
  app/api/          路由（auth/task/collect/ai/scan/vuln/kb/audit…）
  app/services/     采集、研判、探测、深挖、报告等核心服务
  app/models/       SQLAlchemy 模型
  tests/            冒烟测试（smoke_1~6 + 演示站）
  sqlmap_adapter/   SQLMap 进程调用封装
frontend/           Vue 3 前端
docs/               架构 / 数据库 / 部署 / 测试 / 迭代文档
tools/sqlmap/       随项目分发的 SQLMap（GPLv2，版权归原作者）
```

## 环境要求

| 依赖 | 版本 / 说明 |
|---|---|
| 操作系统 | Windows 10/11（双击 `启动mhszed-sql.bat` 或 `start.bat` 即用）；Linux/macOS 可按下方手动命令运行 |
| Python | **3.10+**（实测 3.13.2），需加入 PATH |
| Node.js | **18+**（实测 24.14.0），自带 npm |
| 端口 | `8787`（后端）、`5173`（前端）需空闲；被占用时启动器会提示 |
| SQLMap | 已随项目附带 `tools/sqlmap`，**无需单独安装** |
| 浏览器 | Chrome / Edge（前端为 Vue 3 SPA） |

> Windows 首次运行会**自动**创建虚拟环境并安装后端/前端依赖（需要联网，通常几分钟），
> 之后每次双击即可直接启动，无需再手动执行 `setup.bat`。

## 快速开始（Windows，一键启动）

1. 确认已安装 **Python 3.10+** 和 **Node.js 18+**，并已加入 PATH。
2. **先解压**下载的压缩包（不要在压缩包内直接双击）。
3. 双击 **`启动mhszed-sql.bat`**（或 `start.bat`）。

首次运行会自动完成环境初始化并安装依赖；之后每次双击直接启动。
启动完成后会自动打开 http://localhost:5173，默认账号 **admin / admin123**。

> - 停止服务：关闭 “mhszed-sql backend 8787” 与 “mhszed-sql frontend 5173” 两个控制台窗口。
> - 端口被占用时启动器会明确提示，不会强杀其他程序。
> - 在命令行中运行时请用 `.\start.bat`（避免系统禁止从当前目录直接执行脚本）。
> - 只需要初始化环境时，可单独运行 `.\setup.bat`。

## 手动启动（Linux / macOS / 自定义环境）

```bash
# 1) 后端
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8787

# 2) 前端（另开一个终端）
cd frontend
npm install
npm run dev
```

> 前端开发服务器会把 `/api` 代理到 `http://127.0.0.1:8787`，后端需先启动。

- 默认账号：**admin / admin123**（首次使用请立即修改密码）
- 后端接口文档：http://127.0.0.1:8787/docs
- AI 能力：在「扫描配置」页填写 OpenAI 兼容接口的 base_url / api_key / model；
  未配置时自动降级为规则引擎。
- 数据目录 `backend/data/` 首次启动自动创建，包含 SQLite 数据库与运行产物，**不要提交**。

## 使用指南

### 1. 登录
浏览器打开 http://localhost:5173，使用 `admin / admin123` 登录。
首次登录后请在「扫描配置」页修改默认密码（或通过 `/api/auth/change-password`）。

### 2. 配置授权范围与 AI（扫描配置页）
- **授权范围（必须）**：点「＋ 添加」，填写域名 / 通配符 / IP。
  目标必须落在授权范围内，否则任务启动会被直接拒绝（安全硬约束）。
- **AI 能力（可选）**：填写 OpenAI 兼容接口的 `base_url`、`api_key`、`model`
  （格式见下方「AI 配置标准格式」）。不填时自动降级为规则引擎，功能仍可用。
- 可在同一页调整限速、熔断阈值、探测强度等默认参数。

#### AI 配置标准格式

只有三个字段：

| 字段 | 格式 | 说明 |
|---|---|---|
| `base_url` | `https://<域名>/v1` | OpenAI 兼容根地址，**必须带版本段**；工具自动拼接 `/chat/completions` |
| `api_key` | 服务商密钥 | 加密存储、不回显；再次打开显示为空属正常 |
| `model` | 模型 ID | 以服务商文档为准 |

> ⚠️ `base_url` 末尾不要带 `/`，也不要自己写到 `/chat/completions`（会重复拼接）。

常用服务商：

| 服务商 | base_url | model |
|---|---|---|
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat`（研判推荐）；`deepseek-reasoner` 仅适合短 prompt |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` / `gpt-4o` |
| 阿里云百炼（通义） | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` / `qwen-turbo` |
| Moonshot | `https://api.moonshot.cn/v1` | `moonshot-v1-8k` |
| 智谱 | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` |
| 硅基流动 | `https://api.siliconflow.cn/v1` | `deepseek-ai/DeepSeek-V3` |
| 本地 Ollama | `http://127.0.0.1:11434/v1` | `qwen2.5:7b`（API Key 任意，如 `ollama`） |
| vLLM / LM Studio | `http://127.0.0.1:8000/v1` | 你的模型名（Key 可任意） |

> **Azure OpenAI 不适用**：其 URL 为 `/openai/deployments/<deployment>/chat/completions?api-version=...`，
> 鉴权用 `api-key` 头，与本工具的 `Bearer` + `/v1/chat/completions` 不兼容。

工具实际请求格式（排查用）：

```http
POST {base_url}/chat/completions
Authorization: Bearer {api_key}
Content-Type: application/json

{
  "model": "{model}",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "temperature": 0.2
}
```

- 模型名包含 `reasoner` 时不下发 `temperature`；
- 不使用 `response_format`，靠 prompt 要求 JSON（自动剥除 Markdown 代码围栏）；
- 未配置或连续失败 3 次 → 熔断 300 秒，自动降级规则引擎。

**常见错误**：

| 错误写法 | 现象 | 正确写法 |
|---|---|---|
| `https://platform.deepseek.com` | `405 Method Not Allowed` / TLS 握手超时 | `https://api.deepseek.com/v1` |
| `https://api.deepseek.com`（缺 `/v1`） | 请求路径变成 `/chat/completions`，404/405 | `https://api.deepseek.com/v1` |
| 自己写到 `/chat/completions` | 路径重复，404 | 只写到 `/v1` |
| base_url 末尾带 `/` | 拼接出 `//chat/completions`，部分网关 404 | 去掉末尾 `/` |

> 注意：`platform.deepseek.com` 是网页控制台域名，不是 API 域名。
> 配置错误时日志会出现「AI 调用失败，降级规则引擎」，连续失败 3 次后熔断 300 秒；
> 修正配置后等待冷却结束（或重启后端）即可恢复。

保存前可自测：

```bash
curl -s https://api.deepseek.com/v1/chat/completions \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}'
```

### 3. 创建任务（任务面板）
- 目标 URL：如 `http://127.0.0.1:8899`
- 采集模式：`静态爬虫` / `仅 Burp 流量` / `两者`
- 点击「创建并启动」，任务会依次执行：采集 → WAF 画像 → AI 研判 → 探测 → 复核/完成。
- 每行右侧可查看「日志」、停止任务、删除任务（硬删除，含关联数据）。

### 4. 接口采集（接口采集页）
- 爬虫产出的接口会列在表格中，带方法、参数、读写类型；
- **手动拼接录入**：动态接口（如 `xhr.open('POST','index.php')`）爬虫挖不到时，
  点「＋ 手动拼接录入」，填写方法、路径、参数名与样例值；
- **Burp 推送**：向 `POST /api/burp/push` 推送请求（无需登录态），批量入库；
- 每行操作：
  - **判断**：打开该接口的 AI 判断与探针证据；
  - **扫描**：只对这一个接口做定向重扫（不重新采集，done 任务也可用）；
  - **Payload**：粘贴手工验证成功的 payload，探测器会优先用它做受控对照复测；
  - **删除**：删除接口及其关联扫描记录/漏洞。

### 5. 人工研判复核
- 研判路由：
  - `auto_pass`：自动进入探测；
  - `manual_review` / `suspicious`：停在复核队列，等待人工确认。
- 在「接口采集 → 复核」中确认（confirm）或标记误报（false_positive）；
  确认后点「恢复扫描」（或调用 `POST /api/scan/resume`）继续流水线。
- 误报样本会回流知识库，后续研判自动压制。

### 6. 日志与探测
- 任务行「日志」打开实时日志抽屉：可重连、清屏、**清空日志**（清服务端历史）；
- 探测顺序：AI 探针（带绕过变体）→ SQLMap 初筛；AI 探针确认后为保护目标会跳过 SQLMap；
- 限速默认 1 QPS，熔断器在错误率/拦截率超阈值时暂停任务。

### 7. 漏洞结果与深入利用（漏洞结果页）
- 漏洞默认 `pending_review`，需人工确认后才会回流知识库；
- **深入利用**需选择模式与目标：
  - 模式：`enum`（库表枚举）/ `dump`（受限脱裤，最多 5 行）/ `ai`（AI 规划）；
  - 目标：`schema`（只要一个库名即停）/ `flag`（靶场取 flag）；
- **盲注定向提取**：勾选后允许轻量盲注逐字符提取；失败时读接口会自动回退 sqlmap
  （写接口必须勾选，避免时间盲注真的执行写语句）；
- **证据链摘要按“结果 → 对应 payload/命令”展示**：
  - 数据库名 / 表 / 样本后紧跟真实取数 Payload（sqlmap `-v 3` 的 `[PAYLOAD]`）
    和 `sqlmap 参数`；
  - 盲注额外标注「检测 Payload（非取数语句）」，避免把检测语句误当取数语句；
  - 深挖过程写在证据链中，深挖弹窗只保留入口，不再展示详细日志；
- 结果、证据链（payload / 请求特征 / 响应 / 深挖日志）都会落库，可在漏洞详情查看；
- 报告：`GET /api/vuln/report/download?task_id=<id>` 导出 PDF。

### 8. 知识库与审计
- **知识库**：成功 Payload、误报样本、文章蒸馏知识点；支持按 WAF/向量/DBMS 检索；
- **审计日志**：记录登录、任务、探测、复核、配置变更等；哈希链防篡改；
  支持筛选、单条/批量删除、**清空日志**（清空动作本身会留一条记录）。

### 9. 本地演示靶场
项目自带一个 SQLite demo 站，可用于快速体验：

```bat
cd backend
venv\Scripts\python tests\demo_site.py
:: 访问 http://127.0.0.1:8899
```

在工具中创建任务时把目标填 `http://127.0.0.1:8899`，并在授权范围中添加 `127.0.0.1`。

### 常见问题
| 现象 | 原因 / 处理 |
|---|---|
| `'vite' 不是内部或外部命令` | 未安装前端依赖，先运行 `setup.bat` 或 `npm install` |
| 启动报找不到 `venv\Scripts\python` | 未初始化后端环境，先运行 `setup.bat` |
| 任务启动被拒（403） | 目标不在授权范围，先在「扫描配置」添加范围 |
| 采集到 0 个接口 | 页面接口由 JS/XHR 动态构造，爬虫挖不到；用手动录入或 Burp 推送 |
| 漏洞页没有 WAF 画像 | 未检测到 WAF 或 WAF 阶段被熔断器跳过；只有 `has_waf` 为真时才展示 |
| 任务显示扫描中但没结果 | 目标响应慢/超时触发熔断，探针被拒；等冷却后恢复扫描或换实例 |
| 端口被占用 | 修改启动命令中的 `--port`，同时调整 `frontend/vite.config.js` 的代理地址 |

## 测试

```bat
cd backend
venv\Scripts\python tests\smoke_1.py     :: 授权/任务/爬虫
venv\Scripts\python tests\smoke_2.py     :: WAF/研判/复核
venv\Scripts\python tests\smoke_3.py     :: 端到端 + 报告
venv\Scripts\python tests\smoke_4_deploy.py
venv\Scripts\python tests\smoke_5_bypass.py
venv\Scripts\python tests\smoke_6_evidence_chain.py
:: 新增离线单测（不依赖服务）
venv\Scripts\python tests\test_endpoint_scheme.py
venv\Scripts\python tests\test_counterproof.py
venv\Scripts\python tests\test_resume_flow.py
venv\Scripts\python tests\test_dedupe_recovery.py
venv\Scripts\python tests\test_time_retry.py
venv\Scripts\python tests\test_blind_fallback.py
venv\Scripts\python tests\test_blind_dump.py
venv\Scripts\python tests\test_cross_host_lock.py
```

## 免责声明

1. **仅限授权测试**：本工具只可用于已获得目标所有者**明确书面授权**的安全测试、
   教学与研究。使用者必须在授权范围、授权时间与约定边界内使用。
2. **法律责任自负**：未经授权对他人计算机信息系统进行扫描、探测、入侵或数据获取，
   可能违反《中华人民共和国网络安全法》《中华人民共和国刑法》第二百八十五条、
   第二百八十六条及所在地相关法律法规。由此产生的一切法律责任与后果由**使用者本人**承担，
   作者不参与、不授权、不鼓励任何未授权测试行为。
3. **禁止滥用**：不得将本工具用于破坏系统、批量脱库、横向移动、植入后门、
   拒绝服务或其他危害行为；工具内置的限速/熔断/授权校验仅为降低误操作风险，
   **不能替代使用者的法律责任与合规义务**。
4. **数据与隐私**：请勿在工具中留存与测试无关的个人信息、凭证或敏感数据；
   测试产生的结果应按授权方要求处理或销毁。
5. **部署安全**：默认账号 `admin/admin123` 必须在首次登录后修改；
   不要把服务直接暴露在公网；API Key、数据库与运行产物（`backend/data/`）请妥善保管。
6. **无担保**：本软件按“现状”提供，不附带任何明示或暗示的担保（包括但不限于适销性、
   特定用途适用性与不侵权）。使用本软件造成的任何直接或间接损失，作者不承担责任。
7. **第三方组件**：`tools/sqlmap` 为第三方开源项目（GPLv2），版权归其原作者所有，
   遵循其原始许可；本项目的免责声明不改变第三方组件的许可条款。

**下载、安装或使用本工具，即表示你已阅读、理解并同意以上全部条款。**

## 许可

本项目自身代码采用 **MIT License**，详见根目录 `LICENSE`。

仓库内 `tools/sqlmap` 为第三方项目（GPLv2），以独立子进程方式调用与分发，
遵循其原始许可（见 `tools/sqlmap/LICENSE`），不受本项目 MIT 许可影响。
