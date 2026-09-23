# 12. 多云环境与特权访问管理（IAM & PAM）最小权限治理系统

## 1. 项目背景与对齐 JD 核心点

### 1.1 岗位诉求对齐
* **Senior Cyber Security Analyst (岗位 A)**：
  - **核心职能**：深入理解终端、网络与云架构（Cloud architectures），精通 IAM/PAM 特权访问控制治理，预防横向移动与提权攻击。
  - **调查与取证**：对未授权凭据使用、异常特权提升、长期休眠账号异常激活等事件开展根因调查与控制加固。
* **Senior IT GRC Specialist (岗位 B)**：
  - **合规审计强项**：对接 SOC 2 CC6.1/CC6.2/CC6.3（逻辑访问控制、按角色授权、定期待遇对账与离职权限回收）、ISO 27001:2022（A.5.15 访问控制、A.5.16 身份管理、A.5.17 鉴别信息、A.5.18 访问权）。
  - **PCI DSS v4.0**：Requirement 7（按需知与最小权限原则限制对系统组件的访问）、Requirement 8（唯一身份识别与高危特权 MFA）。
  - **内审与外部检查**：主导每季度组织级账号权限再确认（User Access Review, UAR）并形成审计底稿。

### 1.2 业务痛点与项目定位
在多云（AWS、Azure、GCP）与混合办公环境下，特权管理面临普遍失控：
1. **过度授权与通配符滥用**：开发人员使用 `AdministratorAccess` 或 `Action: "*", Resource: "*"`，攻击者一旦盗取凭据即可接管整云。
2. **休眠与孤儿账号林立**：员工转岗、离职或外部临时供应商撤出后，AK/SK（Access Key）与 IAM 账号长达 90+ 天未清理。
3. **UAR 走过场与缺乏审计链路**：季度权限对账依靠杂乱的 Excel 邮件沟通，经理盲目批量点击“同意”，导致审计师抽查直接开出“重大不符合项”。
4. **紧急提权无记录**：生产故障排查时直接共享 root 或跳板机特权，缺少即时授权（Just-In-Time, JIT）与破窗（Break-Glass）留痕。

本项目搭建一个**云原生 IAM/PAM 最小权限治理与 UAR 自动化中台**：实现全自动检测过度权限与休眠账号、自动派发经理权限审批对账单、集成 JIT 紧急特权破窗审批流，输出符合 SOC 2 / ISO 27001 审计规范的不可篡改凭证。

---

## 2. Mac 本地运行环境架构与依赖

### 2.1 技术栈选型
* **语言**：Python 3.10+
* **前端展示与审批交互**：Streamlit（提供管理员治理大屏与经理 UAR 审批门户）
* **存储**：SQLite / JSON 结构化存储
* **云策略解析**：基于 AWS IAM Policy 规范的 JSON 解析引擎与策略检查器

### 2.2 本地运行架构图
```
   [AWS / Azure IAM JSON Dumps] ─── (Users, Roles, Policies, LastActive)
                 │
                 ▼
     [IAM Governance Analyzer Engine]
       ├── Wildcard / Admin Policy Scanner (Action: *, iam:*, NotAction)
       ├── Dormant / Orphan Account Scanner (>90d inactive, no MFA)
       └── Separation of Duties (SoD) Conflict Detector
                 │
                 ▼
       [Local SQLite Database]
         ├── iam_identities
         ├── access_review_campaigns
         └── break_glass_sessions
                 │
        ┌────────┴─────────────────────────┐
        ▼                                  ▼
[Streamlit Security Portal]       [Auditor Evidence Pack]
 - 过宽权限风险看板                - 季度 UAR 完整闭环签名日志
 - 经理交互式 UAR 审批门户          - JIT 破窗审批与时长控制记录
 - JIT 提权申请与审批
```

### 2.3 依赖清单 (`requirements.txt`)
```txt
streamlit>=1.30.0
pydantic>=2.5.0
pandas>=2.1.0
pytest>=7.4.0
```

---

## 3. Vibe Coding Prompt（可直接复制给 Cursor / Claude Code）

```markdown
Role: Principal Cloud Security Architect & GRC Automation Lead
Task: 开发一个多云特权访问治理与用户访问复核（IAM/PAM Least Privilege & UAR）本地仿真系统。

功能清单：
1. `iam_analyzer.py`：
   - 解析 IAM Policy 文档，检测高危风险项：
     a) 超级管理员权限（Action: "*", Resource: "*"）；
     b) 高危提权 API 组合（如 iam:CreateAccessKey, iam:AttachUserPolicy, iam:PassRole）；
     c) 允许公网/未限制 IP 的 AssumeRole Trust Policy。
   - 分析用户活跃度，检测休眠账户（LastActive > 90 天或未启用 MFA）。
2. `uar_engine.py` (User Access Review 季度对账引擎)：
   - 发起 Q3 访问复核活动（Campaign），将系统/权限自动映射至所属主管（Manager）。
   - 主管审批动作：`Keep (保留并附理由)`、`Revoke (废弃并触发工单)`、`Modify (权限降级)`。
   - 生成符合 SOC 2 CC6.2 审计标准的《季度访问复核审计签字凭单》。
3. `break_glass.py` (JIT / 紧急破窗特权管理)：
   - 申请临时特权提权（指定时间窗口：如 2小时、4小时）。
   - 必填字段：变更/事故工单号（Ticket ID）、申请理由、提权范围（如 ReadOnly 升为 Admin）。
   - 双人复核（Peer/Manager Approval），到期自动撤销，生成审计时间戳。
4. `app.py`：Streamlit 可视化界面：
   - 页面 1：企业云 IAM 风险全景态势（过宽权限分布、休眠账号清单）；
   - 页面 2：主管权限复核工作台（交互式点选 Keep/Revoke 并提交）；
   - 页面 3：JIT Break-Glass 紧急提权监控与审批中心；
   - 页面 4：SOC 2 / ISO 27001 审计证据一键导出。
5. 附带生成包含 20 个模拟 IAM 用户/角色策略的 JSON 样例数据。
```

---

## 4. 核心代码与系统实现

### 4.1 IAM 策略与休眠账户分析引擎 (`iam_analyzer.py`)

```python
import json
import datetime
from typing import List, Dict, Any
from pydantic import BaseModel

DANGEROUS_IAM_ACTIONS = {
    "iam:createaccesskey",
    "iam:createuser",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:passrole",
    "sts:assumerole"
}

class IAMRiskReport(BaseModel):
    account_name: str
    risk_type: str # WILDCARD_ADMIN, PRIVILEGE_ESCALATION, DORMANT_ACCOUNT, NO_MFA
    severity: str  # Critical, High, Medium
    details: str
    recommended_action: str

def evaluate_iam_policy(policy_doc: Dict[str, Any], user_or_role: str) -> List[IAMRiskReport]:
    risks = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        
        # 1. 检查超级管理员通配符
        if "*" in actions and ("*" in resources or not resources):
            risks.append(IAMRiskReport(
                account_name=user_or_role,
                risk_type="WILDCARD_ADMIN",
                severity="Critical",
                details="Policy contains unrestricted 'Action: *' and 'Resource: *'",
                recommended_action="Replace with fine-grained role-based managed policies."
            ))
            continue
        
        # 2. 检查潜在提权危险权限
        lowered_actions = [a.lower() for a in actions]
        matched_priv_esc = [act for act in lowered_actions if act in DANGEROUS_IAM_ACTIONS]
        if matched_priv_esc:
            risks.append(IAMRiskReport(
                account_name=user_or_role,
                risk_type="PRIVILEGE_ESCALATION",
                severity="High",
                details=f"Policy grants dangerous privilege escalation actions: {matched_priv_esc}",
                recommended_action="Scope down IAM privileges with strict Resource ARNs and Permission Boundaries."
            ))
            
    return risks

def check_dormant_accounts(users_data: List[Dict[str, Any]], cutoff_days: int = 90) -> List[IAMRiskReport]:
    risks = []
    today = datetime.date.today()
    
    for u in users_data:
        user_name = u.get("UserName", "Unknown")
        mfa_enabled = u.get("MFAEnabled", False)
        last_active_str = u.get("LastPasswordUseDate")
        
        if not mfa_enabled:
            risks.append(IAMRiskReport(
                account_name=user_name,
                risk_type="NO_MFA",
                severity="High",
                details=f"User {user_name} does not have Multi-Factor Authentication enabled.",
                recommended_action="Enforce strict MFA via AWS Organizations SCP."
            ))
            
        if last_active_str:
            last_active = datetime.datetime.fromisoformat(last_active_str).date()
            inactive_days = (today - last_active).days
            if inactive_days > cutoff_days:
                risks.append(IAMRiskReport(
                    account_name=user_name,
                    risk_type="DORMANT_ACCOUNT",
                    severity="Medium",
                    details=f"User has been inactive for {inactive_days} days (> {cutoff_days} days).",
                    recommended_action="Disable console password and deactivate active Access Keys."
                ))
    return risks
```

### 4.2 季度 UAR 对账与 JIT 紧急提权工作流 (`uar_and_jit.py`)

```python
import uuid
import datetime
from typing import Optional, List
from pydantic import BaseModel

class UARItem(BaseModel):
    item_id: str
    user_name: str
    current_role: str
    assigned_systems: List[str]
    manager_email: str
    decision: str = "PENDING" # PENDING, APPROVED_KEEP, REVOKE, MODIFY
    justification: Optional[str] = None
    reviewed_at: Optional[datetime.datetime] = None

class BreakGlassRequest(BaseModel):
    session_id: str
    requester: str
    target_role: str # e.g. "arn:aws:iam::123456789012:role/EmergencyProductionAdmin"
    ticket_id: str   # e.g. "INC-88912"
    duration_hours: int
    justification: str
    approved_by: Optional[str] = None
    status: str = "REQUESTED" # REQUESTED, ACTIVE, EXPIRED, REVOKED
    start_time: Optional[datetime.datetime] = None
    expiry_time: Optional[datetime.datetime] = None

    def activate(self, approver: str):
        self.approved_by = approver
        self.status = "ACTIVE"
        self.start_time = datetime.datetime.now()
        self.expiry_time = self.start_time + datetime.timedelta(hours=self.duration_hours)

    def is_expired(self) -> bool:
        if self.status != "ACTIVE" or not self.expiry_time:
            return False
        return datetime.datetime.now() > self.expiry_time
```

---

## 5. 测试验证与自动化测试脚本

创建本地测试套件 `test_iam_governance.py`：

```python
import datetime
from iam_analyzer import evaluate_iam_policy, check_dormant_accounts
from uar_and_jit import BreakGlassRequest

def test_wildcard_detection():
    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    risks = evaluate_iam_policy(admin_policy, "admin-dev-user")
    assert len(risks) == 1
    assert risks[0].risk_type == "WILDCARD_ADMIN"
    assert risks[0].severity == "Critical"

def test_dormant_account_scanner():
    mock_users = [{
        "UserName": "contractor-bob",
        "MFAEnabled": False,
        "LastPasswordUseDate": "2025-01-01T00:00:00"
    }]
    risks = check_dormant_accounts(mock_users, cutoff_days=90)
    risk_types = [r.risk_type for r in risks]
    assert "DORMANT_ACCOUNT" in risk_types
    assert "NO_MFA" in risk_types

def test_break_glass_lifecycle():
    req = BreakGlassRequest(
        session_id="BG-101",
        requester="alice@trip.biz",
        target_role="role/EmergencyDBA",
        ticket_id="INC-999",
        duration_hours=2,
        justification="P0 Payment DB failover investigation"
    )
    assert req.status == "REQUESTED"
    
    req.activate(approver="bob_secops_lead@trip.biz")
    assert req.status == "ACTIVE"
    assert req.approved_by == "bob_secops_lead@trip.biz"
    assert req.is_expired() is False

if __name__ == "__main__":
    test_wildcard_detection()
    test_dormant_account_scanner()
    test_break_glass_lifecycle()
    print("All IAM/PAM & UAR governance test cases passed successfully!")
```

---

## 6. 简历包装（STAR 法则）

### 中文版
* **情境（Situation）**：多云环境下存在历史遗留权限过大（多处使用通配符策略）、超 25% 外部承包商账号在项目结束后未回收，季度权限复核（UAR）依靠手动发放 Excel，缺乏审计留痕且导致 SOC 2 CC6.2 与 PCI DSS 审计面临违规风险。
* **任务（Task）**：负责跨 AWS 与内部核心业务系统设计并推广“最小权限与特权访问治理（IAM/PAM）中台”，自动化扫描风险策略、落地季度自动化对账与紧急提权审计机制。
* **行动（Action）**：
  - 编写自动化策略审计引擎，自动定位 `Action: "*"` 与高危提权组（PassRole/AttachPolicy），建立基于使用日志（CloudTrail/LastAccessed）的权限瘦身基线。
  - 构建全自动季度 UAR 工作流，支持直属主管在线“一键审批/吊销”，实现离职与转岗即刻阻断。
  - 引入 JIT（即时授权）Break-Glass 破窗提权规范，强制关联事件工单并实施双人审批，限制临时特权最长生效时间（4小时），操作日志强制归档。
* **结果（Result）**：全组织消除 100% 的不可控通配符管理员权限，清理 180+ 个休眠孤儿账号；季度 UAR 完成周期由 3 周压缩至 4 天，成功作为核心控制证据支持了 SOC 2 Type II 及 ISO 27001 的年度复审。

### English Version
* **Situation**: The organization faced significant cloud identity sprawl with widespread wildcard admin policies, unmanaged vendor accounts, and manual, error-prone quarterly User Access Reviews (UAR), creating compliance risks under SOC 2 CC6.2 and PCI DSS.
* **Task**: Led the design and deployment of an automated Cloud IAM/PAM Least-Privilege Governance and Access Review framework across multi-cloud environments.
* **Action**:
  - Developed an automated IAM policy auditing engine analyzing CloudTrail logs to prune unused permissions and flag dangerous escalation pathways (e.g., PassRole).
  - Architected a streamlined quarterly UAR workflow enabling department managers to review and revoke unnecessary privileges via an interactive portal.
  - Implemented a time-bound Just-In-Time (JIT) Break-Glass mechanism for production access, requiring dual approval, ticket references, and 100% auditable session records.
* **Result**: Eliminated 100% of persistent wildcard admin policies, purged 180+ dormant accounts, cut UAR cycle time from 3 weeks to 4 days, and delivered flawless audit evidence for SOC 2 Type II and ISO 27001 certifications.

---

## 7. 面试高频追问及优秀应答策略

### Q1：在推进“最小权限（Least Privilege）”时，研发往往抱怨权限缩紧导致生产/发布挂掉，你如何推行并取得业务认同？
* **应答策略**：
  - **切忌一刀切硬切断**：采用“分阶段、数据驱动（Data-Driven）”的方式推进，而不是直接大刀阔斧删策略。
  - **第一阶段（分析与可观测）**：利用 AWS IAM Access Advisor / CloudTrail 历史访问日志，分析该 Role / User 在过去 90 天内实际调用过的 API 清单，只授予高频使用的权限，多余的权限生成变更草案。
  - **第二阶段（灰度与预通知）**：在预发与非核心生产服务上先行灰度，向团队负责人提供清晰的变更说明，并建立快速回滚通道。
  - **第三阶段（保障机制）**：提供自助化的 JIT Break-Glass（紧急提权）通道。告知研发：“平时收归最小权限保障合规，一旦发生紧急事故，你可在 2 分钟内通过破窗流程拿到临时特权，绝不耽误排障”。

### Q2：SOC 2 / ISO 27001 审计师在抽查 User Access Review (UAR) 时，最关心的控制漏洞有哪些？
* **应答策略**：
  - **自批自审（Lack of Independence）**：系统管理员不能自己审批自己的权限，必须由其直属上级或独立的业务流程负责人审批。
  - **无理由保留（Rubber-Stamping）**：审计师会挑出拥有敏感生产权限的员工，检查主管是否写明了正当业务理由（Justification），还是全部打勾“Keep”。
  - **复核完成与执行脱节**：如果在 UAR 中主管标记了“Revoke（收回）”，但 IT 运维未在承诺期限（如 48 小时）内实际从云端删除权限，这会被认定为控制失效。必须出示工单执行闭环的时间戳证明。

### Q3：什么是 Break-Glass（破窗机制）？你们是如何防范破窗权限被滥用的？
* **应答策略**：
  - **定义**：Break-Glass 是在发生重大生产故障、系统不可用或灾难恢复等紧急场景下，允许特权人员绕过日常常规审批，获取高特权账号（如 Cloud Root / Domain Admin）的受控机制。
  - **防护与控制闭环**：
    1. **强认证**：破窗账号仅限硬件 Token 或受保护的 Vault 生成的一次性临时凭证；
    2. **关联工单**：必须强制绑定故障工单号（Ticket ID）并通知 SOC / CISO；
    3. **倒计时自动失效**：通常设置严格的时间上限（如 2~4 小时），时间到期后云端凭证自动失效；
    4. **即时报警与事后复核**：破窗账号一旦登录，SOC 立即触发最高优先级的告警（SEV-1）；在事件恢复后 24 小时内，必须对破窗期间执行的所有 CloudTrail 操作进行专项审计复盘。
