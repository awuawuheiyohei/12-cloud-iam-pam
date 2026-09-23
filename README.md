# Cloud IAM/PAM Least Privilege

> **一句话**：FastAPI + 过宽权限检测 + UAR 季度对账 + JIT 紧急提权审计
> 对齐 **Senior IT GRC Specialist** / **Senior Cyber Security Analyst** 岗位核心能力。

---

## ✨ 状态

**v0.1 框架已就绪**（2026-09-23）— 端到端实现在后续 session 深度做。

## 📁 项目结构

```
12-cloud-iam-pam/
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py            # init_db + call_llm + strip_thinking
│   └── main.py                # Web 入口（FastAPI）
├── tests/                      # 测试（待补）
└── docs/
    └── PRD.md                 # 完整需求文档（来自 14-Projects-Plan）
```

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/12-cloud-iam-pam
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

cp .env.example .env  # 编辑填 LLM_API_KEY

WEB_PORT=5039 python main.py serve
# 浏览器: http://localhost:5039/docs
```

## 📝 PRD 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/Interview/Security_and_GRC_14_Projects_Plan/12_Cloud_IAM_PAM_Least_Privilege_Governance.md` 完整规划。

## 📄 License

MIT — 自由使用、修改、二次分发。
