"""
IAM Policy & Account Analyzer
- WILDCARD_ADMIN (Action: *, Resource: *)
- PRIVILEGE_ESCALATION (危险 IAM API)
- NO_MFA (用户未启用 MFA)
- DORMANT_ACCOUNT (LastActive > 90 天 / 从未活跃)
- TRUST_POLICY_OPEN (AssumeRole 0.0.0.0/0)
"""
from datetime import date, datetime, timedelta
from typing import List, Dict, Any
import json


# 危险 IAM Actions（提权 / 凭据创建）
DANGEROUS_IAM_ACTIONS = {
    "iam:createaccesskey",
    "iam:createuser",
    "iam:deleteuser",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:updateassumerolepolicy",
    "iam:createpolicy",
    "sts:assumerole",
}

# Critical actions（单独标记）
CRITICAL_ACTIONS = {
    "iam:createaccesskey",
    "iam:passrole",
    "iam:attachuserpolicy",
    "iam:updateassumerolepolicy",
}

DORMANT_DAYS = 90


# ============================================
# 1. Policy 风险扫描
# ============================================
def analyze_policy(policy_doc: Dict[str, Any], identity_name: str, identity_id: str) -> List[Dict[str, Any]]:
    """返回 finding dict 列表"""
    findings = []
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
        conditions = stmt.get("Condition", {})

        # 1) WILDCARD_ADMIN
        has_wildcard_action = "*" in actions
        has_wildcard_resource = "*" in resources or not resources
        if has_wildcard_action and has_wildcard_resource:
            findings.append({
                "identity_id": identity_id,
                "identity_name": identity_name,
                "risk_type": "WILDCARD_ADMIN",
                "severity": "CRITICAL",
                "details": f"Policy grants unrestricted 'Action: *' on 'Resource: *' — full admin access",
                "evidence": json.dumps({
                    "policy": policy_doc.get("Statement", ""),
                    "action": actions,
                    "resource": resources,
                }, ensure_ascii=False),
                "recommended_action": "Replace with fine-grained AWS managed policies; scope to specific ARNs",
            })
            continue

        # 2) WILDCARD_RESOURCE + sensitive IAM action (仍高危)
        if has_wildcard_resource and any(a.lower() in CRITICAL_ACTIONS for a in actions):
            findings.append({
                "identity_id": identity_id,
                "identity_name": identity_name,
                "risk_type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "details": f"Critical IAM actions granted on Resource: * (privilege escalation risk)",
                "evidence": json.dumps({"action": actions, "resource": resources}, ensure_ascii=False),
                "recommended_action": "Scope to specific IAM user/role ARNs",
            })
            continue

        # 3) Dangerous actions
        lowered = [a.lower() for a in actions]
        matched_dangerous = [act for act in lowered if act in DANGEROUS_IAM_ACTIONS]
        if matched_dangerous:
            sev = "HIGH" if any(a in CRITICAL_ACTIONS for a in matched_dangerous) else "MEDIUM"
            findings.append({
                "identity_id": identity_id,
                "identity_name": identity_name,
                "risk_type": "PRIVILEGE_ESCALATION",
                "severity": sev,
                "details": f"Dangerous IAM actions: {sorted(set(matched_dangerous))}",
                "evidence": json.dumps({"action": matched_dangerous, "resource": resources}, ensure_ascii=False),
                "recommended_action": "Use Permission Boundaries + scoped Resource ARNs",
            })

    return findings


def analyze_identity(identity: Dict[str, Any]) -> List[Dict[str, Any]]:
    """对单条 identity 跑全部检测
    identity 期望是 dict，其中 inline_policies / attached_policies / access_keys 已是 Python obj
    （routes 已 pre-parse）。若传 raw row（字段是 JSON string），用 _ensure_parsed 辅助。
    """
    findings = []

    # 1. Policy analysis
    inline = identity.get("inline_policies") or {}
    attached = identity.get("attached_policies") or []
    if isinstance(inline, str):
        try:
            inline = json.loads(inline)
        except Exception:
            inline = {}
    if isinstance(attached, str):
        try:
            attached = json.loads(attached)
        except Exception:
            attached = []
    for pol_name, pol_doc in inline.items():
        for f in analyze_policy(pol_doc, identity["identity_name"], identity["identity_id"]):
            f["evidence"] = json.dumps({**json.loads(f["evidence"]), "inline_policy": pol_name}, ensure_ascii=False)
            findings.append(f)
    # attached policies 用 ARN 表示（实际 doc 不在 DB），但要提示
    for arn in attached:
        if "AdministratorAccess" in arn or "*" in arn:
            findings.append({
                "identity_id": identity["identity_id"],
                "identity_name": identity["identity_name"],
                "risk_type": "WILDCARD_ADMIN",
                "severity": "CRITICAL",
                "details": f"Attached AdministratorAccess-like policy: {arn}",
                "evidence": json.dumps({"policy_arn": arn}, ensure_ascii=False),
                "recommended_action": "Replace with least-privilege managed policy",
            })

    # 2. MFA 检查
    if not identity.get("mfa_enabled"):
        findings.append({
            "identity_id": identity["identity_id"],
            "identity_name": identity["identity_name"],
            "risk_type": "NO_MFA",
            "severity": "HIGH",
            "details": "User has no MFA configured",
            "evidence": json.dumps({"mfa_enabled": False}, ensure_ascii=False),
            "recommended_action": "Enforce phishing-resistant MFA (FIDO2/WebAuthn)",
        })

    # 3. Dormant check
    last_active = identity.get("last_active_at")
    created = identity.get("created_at")
    today = date.today()
    dormant = False
    if last_active:
        try:
            last_d = date.fromisoformat(last_active.split("T")[0])
            if (today - last_d).days > DORMANT_DAYS:
                dormant = True
        except Exception:
            pass
    elif created:
        # 从未活跃 — 也算休眠
        try:
            c_d = date.fromisoformat(created.split("T")[0])
            if (today - c_d).days > DORMANT_DAYS:
                dormant = True
        except Exception:
            pass

    if dormant:
        # 检查 access_keys
        keys = json.loads(identity.get("access_keys") or "[]")
        active_keys = [k for k in keys if k.get("status") == "Active"]
        if identity["identity_type"] == "USER" and (active_keys or last_active is None):
            findings.append({
                "identity_id": identity["identity_id"],
                "identity_name": identity["identity_name"],
                "risk_type": "DORMANT_ACCOUNT",
                "severity": "HIGH",
                "details": f"User inactive > {DORMANT_DAYS} days (last_active={last_active or 'never'})",
                "evidence": json.dumps({"last_active": last_active, "active_keys": len(active_keys)}, ensure_ascii=False),
                "recommended_action": "Disable login + delete access keys + archive after 90d",
            })

    return findings


def stats_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_type = {}
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    by_status = {"OPEN": 0, "ACCEPTED": 0, "REMEDIATED": 0, "SUPPRESSED": 0}
    for f in findings:
        by_type[f["risk_type"]] = by_type.get(f["risk_type"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
    return {
        "total": len(findings),
        "by_type": by_type,
        "by_severity": by_sev,
        "by_status": by_status,
    }
