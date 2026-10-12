# Cloud IAM/PAM Least Privilege Governance

> **一句话**：Wildcard 权限扫描 + 休眠账户检测 + UAR 季度对账 + JIT Break-Glass 双人审批
> 对齐 **Senior Cyber Security Analyst** IAM/PAM 治理职责 + **SOC 2 CC6.1-6.3 / ISO 27001 A.5.15-18 / PCI DSS Req 7-8**。

---

## ✨ 状态

**v0.1 完成**（2026-09-23）— 端到端实跑：**40/40 tests PASS**

| 模块 | 完成度 | 备注 |
|---|---|---|
| 4 大风险检测 | ✅ | WILDCARD_ADMIN / PRIVILEGE_ESCALATION / NO_MFA / DORMANT_ACCOUNT |
| IAM Policy 解析 | ✅ | Wildcard + IAM:* + Dangerous IAM actions (PassRole/CreateAccessKey 等) |
| 20 Mock Identities | ✅ | 5 高风险 + 15 干净/中等 |
| UAR 季度对账 | ✅ | Q3 2026 campaign + 18 pending manager decisions |
| JIT Break-Glass | ✅ | 双人审批 (peer ≠ requester) + 到期自动 EXPIRED + REVOKE |
| KEEP 强制 justification | ✅ | SOC 2 CC6.2 审计要求 |
| REVOKE 自动 INACTIVE + REMEDIATED findings | ✅ | |
| FastAPI 12 endpoints | ✅ | |
| Vanilla JS Dashboard 5 tab | ✅ | 0 CDN |
| 端到端测试 | ✅ | **40/40 PASS** |
| GitHub public | ✅ | `awuawuheiyohei/12-cloud-iam-pam` |

## 📁 项目结构

```
12-cloud-iam-pam/
├── README.md
├── pyproject.toml
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI app
│   ├── schema.sql             # 5 张表
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py          # 12 endpoints
│   └── models/
│       ├── __init__.py
│       ├── db.py              # SQLite + WAL
│       ├── iam_analyzer.py    # Policy parser + risk detection
│       └── seed.py            # 20 identities + 15 findings + 18 UAR + 2 BG
├── static/
│   └── index.html             # Dashboard 5 tab
├── tests/
│   └── test_routes.py         # 40 tests
└── docs/
    └── PRD.md
```

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/12-cloud-iam-pam
pip install fastapi uvicorn

python main.py serve
# 浏览器: http://localhost:5039/

pytest tests/ -v
```

## 🔑 核心 API

| Endpoint | 方法 | 说明 |
|---|---|---|
| `/health` | GET | 健康检查 |
| `/api/dashboard/summary` | GET | 4 metric card |
| `/api/identities` | GET | 身份清单（filter: type/status/mfa） |
| `/api/identities/{id}` | GET | 身份详情 + findings |
| `/api/identities/{id}/rescan` | POST | 重跑 analyzer |
| `/api/findings` | GET | 风险清单（filter: type/severity/status） |
| `/api/findings/{id}/status` | PATCH | OPEN/ACCEPTED/REMEDIATED/SUPPRESSED |
| `/api/uar/campaigns` | GET | 季度对账列表 |
| `/api/uar/decisions` | GET | 决策列表（filter: campaign/manager/decision） |
| `/api/uar/decisions/{id}` | POST | KEEP/REVOKE/MODIFY |
| `/api/break-glass` | GET | JIT session 列表 |
| `/api/break-glass/request` | POST | 申请 |
| `/api/break-glass/{id}/approve` | POST | 双人审批 |
| `/api/break-glass/{id}/revoke` | POST | 撤销 |
| `/api/break-glass/expire-check` | POST | 自动过期 |
| `/api/report/soc2` | GET | SOC 2 + ISO 27001 + PCI DSS 联合报告 |
| `/api/audit` | GET | 审计 trail |
| `/api/admin/seed` | POST | 重置 |

## 🔍 4 大风险检测

| 类型 | 触发 | 严重度 |
|---|---|---|
| **WILDCARD_ADMIN** | `Action: *` on `Resource: *` 或 AdministratorAccess 托管策略 | CRITICAL |
| **PRIVILEGE_ESCALATION** | `iam:PassRole/CreateAccessKey/AttachUserPolicy` 等危险 IAM API（尤其 Resource:*） | CRITICAL/HIGH |
| **NO_MFA** | 活跃 USER 未启用 MFA | HIGH |
| **DORMANT_ACCOUNT** | LastActive > 90 天 或从未活跃（带 active keys） | HIGH |

## 📊 Dashboard 5 Tab

1. **🚨 风险发现** — 按类型/严重度过滤 + REMEDIATE/ACCEPT/SUPPRESS 一键操作
2. **👤 身份清单** — 20 identities 按 type/MFA 过滤 + 详情查看
3. **📝 UAR 审批** — Manager Keep/Revoke/Modify 决策流（KEEP 强制 justification）
4. **🚨 Break-Glass** — JIT session 申请/审批/撤销 + 自动过期
5. **📊 SOC 2 报告** — CC6 + ISO 27001 + PCI DSS 联合报告

## 🧪 测试覆盖（40/40 PASS）

- IAM Analyzer (policy + identity): 9 个
- Seed data: 4 个
- Identities API: 6 个
- Findings API: 4 个
- UAR API: 5 个
- Break-Glass API: 7 个
- Report + Audit + Static: 5 个
- 关键场景：
  - Wildcard policy → CRITICAL
  - iam:PassRole on Resource:* → CRITICAL
  - REVOKE → 自动 INACTIVE + REMEDIATED findings
  - KEEP without justification → 400
  - Self approval → 400

## 📝 PRD 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/25-Interview/Security_and_GRC_14_Projects_Plan/12_Cloud_IAM_PAM_Least_Privilege_Governance.md` 完整规划。

## 📄 License

MIT — 自由使用、修改、二次分发。
