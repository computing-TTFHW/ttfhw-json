---
name: ttfhw-json-validator
description: 验证 reports/ 目录中的 TTFHW JSON 验证报告的结构完整性、类型正确性、安全风险和语义一致性。结合确定性规则检查和 AI 语义分析。当用户需要验证 JSON 报告质量、检查新增报告的规范性、在提交 PR 前进行质量门禁检查、或审查报告是否有注入/安全风险时触发。
---

# TTFHW JSON Validator

验证 `reports/` 目录中的 TTFHW 验证报告 JSON 文件，检查四个维度：

1. **格式正确性** — 结构、类型、时间戳、数值一致性
2. **敏感信息扫描** — 云凭证、Token、数据库连接串、PII、内网信息、高熵字符串
3. **安全风险** — 注入检测（shell/XSS/AI prompt injection）
4. **语义合理性** — AI 驱动的中文语义分析

## 调用方式

```bash
# 确定性检查（结构、类型、注入检测）
python3 scripts/validate_json.py reports/*.json

# 敏感信息扫描（云凭证、Token、PII 等）
python3 scripts/scan_sensitive_info.py reports/*.json

# AI 语义分析（需要 DEEPSEEK_API_KEY）
python3 scripts/ai_quality_check.py reports/<file>.json
```

## 标准模板

验证依据的标准模板位于：
https://github.com/computing-TTFHW/ttfhw-report/blob/master/.claude/skills/ttfhw-verify-openeuler/assets/report_template.json

## 检查项目

### 格式正确性（18 项确定性检查）

| 检查项 | 严重级别 |
|--------|----------|
| 合法 JSON 解析 | ERROR |
| 8 个顶级 key 存在且匹配模板 | ERROR |
| metadata 5 字段完整性 | ERROR |
| ISO 8601 时间戳格式 | ERROR |
| 字段类型正确性 (bool/int/null) | ERROR |
| pre_commit: passed+failed+skipped == total_hooks | ERROR |
| duration_seconds 自洽 | WARNING |
| 模板结构深度对比 | WARNING |
| 条件字段存在性 (failure_reason) | WARNING |
| 时间戳单调性 | WARNING |
| 多余/未知 key 标记 | INFO |
| Docker 守护进程一致性 | WARNING |
| 空数组合理性 | INFO |
| failure_reason 简短检查 | WARNING |

### 敏感信息扫描（8 个检测维度，独立脚本 `scan_sensitive_info.py`）

| 检查项 | 严重级别 |
|--------|----------|
| 云厂商凭证 (AWS/Huawei/Tencent/Alibaba/Azure) | ERROR |
| 代码托管 Token (GitHub/GitLab/GitCode) | ERROR |
| 通信平台 Token (Slack/Telegram/Discord/Lark) | ERROR |
| 数据库连接串 (含用户名密码) | ERROR |
| 私钥 / JWT / Bearer Token / OpenAI Key | ERROR |
| 通用密钥赋值 (password=/api_key=/token= 等) | ERROR |
| 中国身份证号 | ERROR |
| 邮箱地址 / 手机号 | WARNING |
| 私有 IP 地址 / MAC 地址 | WARNING/NOTICE |
| 高熵字符串（疑似编码密钥） | WARNING |

**误报控制**：自动跳过 CJK 中文文本、文件名、git SSH URL、Conan 包版本号、已知占位符值（N/A/xxx/your_password 等）。

### AI 语义分析（6 个检查维度）

| 检查项 | 说明 |
|--------|------|
| 状态值一致性 | build/ut/sample 的 status 取值是否合理 |
| failure_reason 质量 | 是否具体可操作还是泛泛占位符 |
| documentation_gaps 质量 | 是否具体有分类 |
| problems_encountered 闭环 | problem→solution 是否完整 |
| process_timeline 匹配 | details 与 step 类型是否一致 |
| 跨段矛盾 | 报告各部分之间的逻辑一致性 |

## 输出格式

验证结果以结构化 JSON 输出，每个 issue 包含：
- `severity`: error | warning | notice
- `check`: 检查类型名称
- `path`: JSON 路径 (如 `$.final_results.build.status`)
- `message`: 中文描述

## 常见问题及修复

| 问题 | 修复 |
|------|------|
| `failure_reason` 缺失但 status 非"成功" | 添加 `failure_reason` 字段到对应的 final_results section |
| `cpu_cores` 为字符串 "N/A" | 改用 `null` 或整数 |
| `container.memory` 缺失 | 至少添加 `"memory": "N/A"` |
| Unknown key 告警 | 确认是否为拼写错误；若是新版字段，更新模板 |
| shell 注入告警 | 检查描述性字段中是否有多余的 shell 命令语法 |

## 环境变量

- `DEEPSEEK_API_KEY` — 可选，设置后启用 DeepSeek v4-pro AI 语义分析。未设置时 AI 分析自动跳过。

## AI 模型

使用 DeepSeek v4-pro（via OpenAI SDK 兼容接口），启用 reasoning_effort="high" + thinking 模式，提供更深入的中文语义分析。

## Token 注入防护

AI 分析脚本 (`ai_quality_check.py`) 内置多层注入防护：

1. **文件大小限制** — 拒绝超过 1MB 的文件
2. **字符串长度截断** — 超过 50000 字符的单个值会被截断
3. **提示词注入检测** — 检测 "ignore previous instructions"、系统提示词覆盖、角色劫持等 7 类注入模式
4. **Token 炸弹检测** — 通过 zlib 压缩比识别重复填充内容
5. **总 Token 预算** — 预估超过 30000 token 时拒绝分析
6. **数组长度限制** — 超过 500 项的数组截断处理
