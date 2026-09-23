"""
IAM/PAM Least Privilege API Routes
- Identities / Findings / UAR / Break-Glass / Audit / Report
"""
import json
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Body, Query
from pydantic import BaseModel, Field

from ..models.db import get_conn, init_db, row_to_dict, rows_to_dicts, write_audit, db_connection
from ..models.iam_analyzer import analyze_identity, stats_summary
from ..models.seed import seed_all

router = APIRouter()


# ============================================
# Pydantic
# ============================================
class UARDecisionReq(BaseModel):
    decision: str = Field(..., pattern="^(KEEP|REVOKE|MODIFY)$")
    justification: Optional[str] = None
    modified_policies: List[str] = []


class BreakGlassRequest(BaseModel):
    identity_id: str
    requested_role: str
    duration_minutes: int = Field(120, ge=15, le=480)
    reason: str
    ticket_id: str


class BreakGlassApproval(BaseModel):
    peer_approver: str


# ============================================
# Dashboard
# ============================================
@router.get("/dashboard/summary")
async def dashboard_summary():
    init_db()
    conn = get_conn()
    n_id = conn.execute("SELECT COUNT(*) FROM iam_identities").fetchone()[0]
    n_active = conn.execute("SELECT COUNT(*) FROM iam_identities WHERE status='ACTIVE'").fetchone()[0]
    n_no_mfa = conn.execute("SELECT COUNT(*) FROM iam_identities WHERE mfa_enabled=0 AND status='ACTIVE' AND identity_type='USER'").fetchone()[0]
    n_findings = conn.execute("SELECT COUNT(*) FROM iam_risk_findings WHERE status='OPEN'").fetchone()[0]
    f_by_type = rows_to_dicts(conn.execute(
        "SELECT risk_type, COUNT(*) as cnt FROM iam_risk_findings WHERE status='OPEN' GROUP BY risk_type ORDER BY cnt DESC"
    ).fetchall())
    f_by_sev = rows_to_dicts(conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM iam_risk_findings WHERE status='OPEN' GROUP BY severity"
    ).fetchall())
    # UAR
    n_campaigns = conn.execute("SELECT COUNT(*) FROM access_review_campaigns").fetchone()[0]
    n_uar_pending = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE decision='PENDING'").fetchone()[0]
    n_uar_kept = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE decision='KEEP'").fetchone()[0]
    n_uar_revoked = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE decision='REVOKE'").fetchone()[0]
    # Break-Glass
    n_bg_active = conn.execute("SELECT COUNT(*) FROM break_glass_sessions WHERE status='ACTIVE'").fetchone()[0]
    n_bg_pending = conn.execute("SELECT COUNT(*) FROM break_glass_sessions WHERE status='PENDING'").fetchone()[0]
    return {
        "identities": {"total": n_id, "active": n_active, "no_mfa_active": n_no_mfa},
        "findings": {"open": n_findings, "by_type": f_by_type, "by_severity": f_by_sev},
        "uar": {"campaigns": n_campaigns, "pending": n_uar_pending, "kept": n_uar_kept, "revoked": n_uar_revoked},
        "break_glass": {"active": n_bg_active, "pending": n_bg_pending},
    }


# ============================================
# Identities
# ============================================
@router.get("/identities")
async def list_identities(identity_type: Optional[str] = None,
                          status: Optional[str] = None,
                          mfa_enabled: Optional[bool] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM iam_identities WHERE 1=1"
    params = []
    if identity_type:
        sql += " AND identity_type=?"
        params.append(identity_type)
    if status:
        sql += " AND status=?"
        params.append(status)
    if mfa_enabled is not None:
        sql += " AND mfa_enabled=?"
        params.append(1 if mfa_enabled else 0)
    sql += " ORDER BY identity_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    for r in rows:
        try:
            r["access_keys"] = json.loads(r["access_keys"]) if r["access_keys"] else []
            r["attached_policies"] = json.loads(r["attached_policies"]) if r["attached_policies"] else []
            r["inline_policies"] = json.loads(r["inline_policies"]) if r["inline_policies"] else {}
        except Exception:
            pass
    return {"count": len(rows), "items": rows}


@router.get("/identities/{identity_id}")
async def get_identity(identity_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM iam_identities WHERE identity_id=?", (identity_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Identity not found: {identity_id}")
    d = row_to_dict(row)
    try:
        d["access_keys"] = json.loads(d["access_keys"]) if d["access_keys"] else []
        d["attached_policies"] = json.loads(d["attached_policies"]) if d["attached_policies"] else []
        d["inline_policies"] = json.loads(d["inline_policies"]) if d["inline_policies"] else {}
    except Exception:
        pass
    # Findings
    d["findings"] = rows_to_dicts(conn.execute(
        "SELECT * FROM iam_risk_findings WHERE identity_id=? ORDER BY severity", (identity_id,)
    ).fetchall())
    return d


@router.post("/identities/{identity_id}/rescan")
async def rescan_identity(identity_id: str, actor: str = "grc-team"):
    """重新跑 analyzer 并刷新 findings（旧的删，新的加）"""
    conn = get_conn()
    row = conn.execute("SELECT * FROM iam_identities WHERE identity_id=?", (identity_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Identity not found: {identity_id}")
    ident = row_to_dict(row)
    try:
        ident["inline_policies"] = json.loads(ident["inline_policies"]) if ident["inline_policies"] else {}
        ident["attached_policies"] = json.loads(ident["attached_policies"]) if ident["attached_policies"] else []
        ident["access_keys"] = json.loads(ident["access_keys"]) if ident["access_keys"] else []
    except Exception:
        pass
    findings = analyze_identity(ident)
    conn.execute("DELETE FROM iam_risk_findings WHERE identity_id=?", (identity_id,))
    # 从现有最大 fid 解析下一个号，避免 UNIQUE 冲突
    row = conn.execute(
        "SELECT MAX(CAST(SUBSTR(finding_id, 3) AS INTEGER)) FROM iam_risk_findings"
    ).fetchone()
    n = (row[0] or 0)
    for f in findings:
        n += 1
        fid = f"F-{n:04d}"
        conn.execute(
            """INSERT INTO iam_risk_findings (finding_id, identity_id, identity_name, risk_type, severity, details, evidence, recommended_action, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
            (fid, f["identity_id"], f["identity_name"], f["risk_type"], f["severity"],
             f["details"], f["evidence"], f["recommended_action"])
        )
    write_audit(conn, actor=actor, action="rescan_identity",
                entity_type="iam_identities", entity_id=identity_id,
                details={"findings": len(findings)})
    conn.commit()
    return {"identity_id": identity_id, "findings_count": len(findings)}


# ============================================
# Findings
# ============================================
@router.get("/findings")
async def list_findings(risk_type: Optional[str] = None,
                        severity: Optional[str] = None,
                        status: Optional[str] = "OPEN"):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM iam_risk_findings WHERE 1=1"
    params = []
    if risk_type:
        sql += " AND risk_type=?"
        params.append(risk_type)
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END, finding_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, status: str, actor: str = "grc-team"):
    if status not in ("OPEN", "ACCEPTED", "REMEDIATED", "SUPPRESSED"):
        raise HTTPException(400, "Invalid status")
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM iam_risk_findings WHERE finding_id=?", (finding_id,)).fetchone():
        raise HTTPException(404, f"Finding not found: {finding_id}")
    conn.execute("UPDATE iam_risk_findings SET status=? WHERE finding_id=?", (status, finding_id))
    write_audit(conn, actor=actor, action="update_finding",
                entity_type="iam_risk_findings", entity_id=finding_id, details={"status": status})
    conn.commit()
    return {"finding_id": finding_id, "status": status}


# ============================================
# UAR Campaigns
# ============================================
@router.get("/uar/campaigns")
async def list_campaigns():
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute("SELECT * FROM access_review_campaigns ORDER BY due_date DESC").fetchall())
    for r in rows:
        n_total = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE campaign_id=?", (r["campaign_id"],)).fetchone()[0]
        n_pending = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE campaign_id=? AND decision='PENDING'", (r["campaign_id"],)).fetchone()[0]
        n_kept = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE campaign_id=? AND decision='KEEP'", (r["campaign_id"],)).fetchone()[0]
        n_revoked = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE campaign_id=? AND decision='REVOKE'", (r["campaign_id"],)).fetchone()[0]
        r["decisions_total"] = n_total
        r["decisions_pending"] = n_pending
        r["decisions_kept"] = n_kept
        r["decisions_revoked"] = n_revoked
        r["progress_pct"] = round((n_total - n_pending) / n_total * 100, 1) if n_total else 0
    return {"count": len(rows), "items": rows}


@router.get("/uar/decisions")
async def list_decisions(campaign_id: Optional[str] = None, manager: Optional[str] = None,
                         decision: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM access_review_decisions WHERE 1=1"
    params = []
    if campaign_id:
        sql += " AND campaign_id=?"
        params.append(campaign_id)
    if manager:
        sql += " AND manager=?"
        params.append(manager)
    if decision:
        sql += " AND decision=?"
        params.append(decision)
    sql += " ORDER BY decision_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    for r in rows:
        try:
            r["modified_policies"] = json.loads(r["modified_policies"]) if r["modified_policies"] else []
        except Exception:
            r["modified_policies"] = []
    return {"count": len(rows), "items": rows}


@router.post("/uar/decisions/{decision_id}")
async def decide_uar(decision_id: str, req: UARDecisionReq, actor: str = "manager"):
    if req.decision == "KEEP" and not req.justification:
        raise HTTPException(400, "KEEP requires justification")
    conn = get_conn()
    row = conn.execute("SELECT * FROM access_review_decisions WHERE decision_id=?", (decision_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Decision not found: {decision_id}")
    if row["decision"] != "PENDING":
        raise HTTPException(400, f"Decision already made: {row['decision']}")

    today = datetime.now().isoformat()
    conn.execute(
        """UPDATE access_review_decisions SET decision=?, justification=?, modified_policies=?, decided_at=?
           WHERE decision_id=?""",
        (req.decision, req.justification,
         json.dumps(req.modified_policies, ensure_ascii=False) if req.modified_policies else None,
         today, decision_id)
    )
    # REVOKE → 触发 identity 状态更新（INACTIVE）
    if req.decision == "REVOKE":
        conn.execute("UPDATE iam_identities SET status='INACTIVE' WHERE identity_id=?",
                     (row["identity_id"],))
        # 把对应 findings 标 REMEDIATED
        conn.execute("UPDATE iam_risk_findings SET status='REMEDIATED' WHERE identity_id=? AND status='OPEN'",
                     (row["identity_id"],))
    elif req.decision == "MODIFY" and req.modified_policies:
        conn.execute("UPDATE iam_risk_findings SET status='REMEDIATED' WHERE identity_id=? AND status='OPEN'",
                     (row["identity_id"],))

    write_audit(conn, actor=actor, action="decide_uar",
                entity_type="access_review_decisions", entity_id=decision_id,
                details={"decision": req.decision})
    conn.commit()
    return {"decision_id": decision_id, "decision": req.decision, "decided_at": today}


# ============================================
# Break-Glass (JIT)
# ============================================
@router.get("/break-glass")
async def list_bg(status: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM break_glass_sessions WHERE 1=1"
    params = []
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY requested_at DESC"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/break-glass/request")
async def request_bg(req: BreakGlassRequest, actor: str = "requester"):
    init_db()
    conn = get_conn()
    ident = conn.execute("SELECT identity_name FROM iam_identities WHERE identity_id=?",
                         (req.identity_id,)).fetchone()
    if not ident:
        raise HTTPException(400, f"Identity not found: {req.identity_id}")
    n = conn.execute("SELECT COUNT(*) FROM break_glass_sessions").fetchone()[0]
    bg_id = f"BG-{n + 1:04d}"
    conn.execute(
        """INSERT INTO break_glass_sessions
           (bg_id, identity_id, identity_name, requested_role, duration_minutes, reason, ticket_id, requester, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')""",
        (bg_id, req.identity_id, ident["identity_name"], req.requested_role,
         req.duration_minutes, req.reason, req.ticket_id, actor)
    )
    write_audit(conn, actor=actor, action="request_break_glass",
                entity_type="break_glass_sessions", entity_id=bg_id,
                details={"identity_id": req.identity_id, "duration_min": req.duration_minutes})
    conn.commit()
    return {"bg_id": bg_id, "status": "PENDING"}


@router.post("/break-glass/{bg_id}/approve")
async def approve_bg(bg_id: str, req: BreakGlassApproval, actor: str = "peer"):
    conn = get_conn()
    row = conn.execute("SELECT * FROM break_glass_sessions WHERE bg_id=?", (bg_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Session not found: {bg_id}")
    if row["status"] != "PENDING":
        raise HTTPException(400, f"Session already {row['status']}")
    if req.peer_approver == row["requester"]:
        raise HTTPException(400, "Peer approver cannot be the requester")

    now = datetime.now()
    starts = now
    expires = now + timedelta(minutes=row["duration_minutes"])
    conn.execute(
        """UPDATE break_glass_sessions SET status='ACTIVE', peer_approver=?, approved_at=?, starts_at=?, expires_at=?
           WHERE bg_id=?""",
        (req.peer_approver, now.isoformat(), starts.isoformat(), expires.isoformat(), bg_id)
    )
    write_audit(conn, actor=req.peer_approver, action="approve_break_glass",
                entity_type="break_glass_sessions", entity_id=bg_id, details={})
    conn.commit()
    return {"bg_id": bg_id, "status": "ACTIVE", "expires_at": expires.isoformat()}


@router.post("/break-glass/{bg_id}/revoke")
async def revoke_bg(bg_id: str, actor: str = "security"):
    conn = get_conn()
    row = conn.execute("SELECT * FROM break_glass_sessions WHERE bg_id=?", (bg_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Session not found: {bg_id}")
    if row["status"] not in ("ACTIVE", "PENDING"):
        raise HTTPException(400, f"Cannot revoke {row['status']}")
    conn.execute(
        "UPDATE break_glass_sessions SET status='REVOKED', revoked_at=? WHERE bg_id=?",
        (datetime.now().isoformat(), bg_id)
    )
    write_audit(conn, actor=actor, action="revoke_break_glass",
                entity_type="break_glass_sessions", entity_id=bg_id, details={})
    conn.commit()
    return {"bg_id": bg_id, "status": "REVOKED"}


@router.post("/break-glass/expire-check")
async def expire_check(actor: str = "system"):
    """检查并把过期的 ACTIVE session 标记 EXPIRED"""
    conn = get_conn()
    now = datetime.now().isoformat()
    rows = conn.execute(
        "SELECT bg_id FROM break_glass_sessions WHERE status='ACTIVE' AND expires_at < ?",
        (now,)
    ).fetchall()
    for r in rows:
        conn.execute("UPDATE break_glass_sessions SET status='EXPIRED' WHERE bg_id=?", (r["bg_id"],))
        write_audit(conn, actor=actor, action="auto_expire_break_glass",
                    entity_type="break_glass_sessions", entity_id=r["bg_id"], details={})
    conn.commit()
    return {"expired_count": len(rows)}


# ============================================
# SOC 2 / ISO 27001 报告
# ============================================
@router.get("/report/soc2")
async def report_soc2():
    init_db()
    conn = get_conn()
    today = datetime.now().isoformat()
    n_users = conn.execute("SELECT COUNT(*) FROM iam_identities WHERE identity_type='USER'").fetchone()[0]
    n_no_mfa = conn.execute("SELECT COUNT(*) FROM iam_identities WHERE mfa_enabled=0 AND identity_type='USER' AND status='ACTIVE'").fetchone()[0]
    n_dormant = conn.execute("SELECT COUNT(*) FROM iam_risk_findings WHERE risk_type='DORMANT_ACCOUNT' AND status='OPEN'").fetchone()[0]
    n_wildcard = conn.execute("SELECT COUNT(*) FROM iam_risk_findings WHERE risk_type='WILDCARD_ADMIN' AND status='OPEN'").fetchone()[0]
    uar_campaigns = conn.execute("SELECT COUNT(*) FROM access_review_campaigns").fetchone()[0]
    uar_completed = conn.execute("SELECT COUNT(*) FROM access_review_decisions WHERE decision != 'PENDING'").fetchone()[0]
    bg_total = conn.execute("SELECT COUNT(*) FROM break_glass_sessions").fetchone()[0]
    bg_expired = conn.execute("SELECT COUNT(*) FROM break_glass_sessions WHERE status='EXPIRED'").fetchone()[0]
    return {
        "report_date": today,
        "framework": "SOC 2 CC6.1/CC6.2/CC6.3 + ISO 27001 A.5.15-18 + PCI DSS Req 7/8",
        "iam": {
            "total_users": n_users,
            "users_without_mfa": n_no_mfa,
            "mfa_coverage_pct": round((n_users - n_no_mfa) / n_users * 100, 1) if n_users else 0,
            "open_dormant_accounts": n_dormant,
            "open_wildcard_admin": n_wildcard,
        },
        "uar": {
            "campaigns": uar_campaigns,
            "completed_decisions": uar_completed,
        },
        "break_glass": {
            "total_sessions": bg_total,
            "expired_sessions": bg_expired,
        },
    }


# ============================================
# Audit + Admin
# ============================================
@router.get("/audit")
async def list_audit(limit: int = Query(50, ge=1, le=500)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM audit_trail ORDER BY occurred_at DESC LIMIT ?", (limit,)).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/admin/seed")
async def admin_seed(actor: str = "grc-team"):
    init_db()
    stats = seed_all(verbose=False)
    conn = get_conn()
    write_audit(conn, actor=actor, action="reseed",
                entity_type="system", entity_id="all", details=stats)
    conn.commit()
    return {"status": "ok", "stats": stats}
