-- Cloud IAM/PAM Least Privilege Governance - SQLite schema (v1.0)
-- 依据 Security_and_GRC_14_Projects_Plan #12 PRD

-- ============================================
-- IAM 身份 (User/Role/Group)
-- ============================================
CREATE TABLE IF NOT EXISTS iam_identities (
    identity_id        TEXT PRIMARY KEY,                  -- IAM-001
    identity_name      TEXT NOT NULL,                    -- alice@tripbiz.com
    identity_type      TEXT NOT NULL,                    -- USER / ROLE / GROUP
    identity_arn       TEXT,
    account_id         TEXT NOT NULL,                    -- AWS 账户 / Azure tenant
    email              TEXT,
    manager            TEXT,                             -- 经理（UAR 审批人）
    mfa_enabled        INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    last_active_at     TEXT,                             -- 最后活跃时间（NULL = 从未活跃）
    password_last_set  TEXT,
    access_keys        TEXT NOT NULL DEFAULT '[]',       -- JSON array
    status             TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE / INACTIVE / TERMINATED
    attached_policies  TEXT NOT NULL DEFAULT '[]',       -- JSON array of policy ARNs
    inline_policies    TEXT NOT NULL DEFAULT '{}',       -- JSON dict {name: doc}
    notes              TEXT,
    updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_id_type ON iam_identities(identity_type);
CREATE INDEX IF NOT EXISTS idx_id_status ON iam_identities(status);
CREATE INDEX IF NOT EXISTS idx_id_manager ON iam_identities(manager);

-- ============================================
-- IAM 风险发现 (Risk Findings)
-- ============================================
CREATE TABLE IF NOT EXISTS iam_risk_findings (
    finding_id         TEXT PRIMARY KEY,                  -- F-001
    identity_id        TEXT NOT NULL,
    identity_name      TEXT NOT NULL,
    risk_type          TEXT NOT NULL,                     -- WILDCARD_ADMIN / PRIVILEGE_ESCALATION / DORMANT_ACCOUNT / NO_MFA / TRUST_POLICY_OPEN
    severity           TEXT NOT NULL,                     -- CRITICAL / HIGH / MEDIUM
    details            TEXT NOT NULL,
    evidence           TEXT,                              -- JSON: {policy_arn, statement, action}
    recommended_action TEXT,
    status             TEXT NOT NULL DEFAULT 'OPEN',       -- OPEN / ACCEPTED / REMEDIATED / SUPPRESSED
    detected_at        TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (identity_id) REFERENCES iam_identities(identity_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_type ON iam_risk_findings(risk_type);
CREATE INDEX IF NOT EXISTS idx_finding_sev ON iam_risk_findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_status ON iam_risk_findings(status);

-- ============================================
-- 访问复核 Campaign (UAR)
-- ============================================
CREATE TABLE IF NOT EXISTS access_review_campaigns (
    campaign_id        TEXT PRIMARY KEY,                  -- UAR-2026-Q3
    campaign_name      TEXT NOT NULL,
    quarter            TEXT NOT NULL,                     -- 2026-Q3
    started_at         TEXT NOT NULL DEFAULT (datetime('now')),
    due_date           TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'IN_PROGRESS', -- IN_PROGRESS / COMPLETED
    description        TEXT
);

-- ============================================
-- UAR 决策（每个 identity 的 manager 审批）
-- ============================================
CREATE TABLE IF NOT EXISTS access_review_decisions (
    decision_id        TEXT PRIMARY KEY,                  -- UAR-DEC-001
    campaign_id        TEXT NOT NULL,
    identity_id        TEXT NOT NULL,
    identity_name      TEXT NOT NULL,
    manager            TEXT NOT NULL,
    decision           TEXT NOT NULL,                     -- PENDING / KEEP / REVOKE / MODIFY
    justification      TEXT,                              -- KEEP 必须填
    modified_policies  TEXT,                              -- JSON array of policy ARNs to remove (MODIFY)
    decided_at         TEXT,
    FOREIGN KEY (campaign_id) REFERENCES access_review_campaigns(campaign_id),
    FOREIGN KEY (identity_id) REFERENCES iam_identities(identity_id)
);

CREATE INDEX IF NOT EXISTS idx_uar_campaign ON access_review_decisions(campaign_id);
CREATE INDEX IF NOT EXISTS idx_uar_decision ON access_review_decisions(decision);
CREATE INDEX IF NOT EXISTS idx_uar_manager ON access_review_decisions(manager);

-- ============================================
-- Break-Glass JIT 提权会话
-- ============================================
CREATE TABLE IF NOT EXISTS break_glass_sessions (
    bg_id              TEXT PRIMARY KEY,                  -- BG-001
    identity_id        TEXT NOT NULL,
    identity_name      TEXT NOT NULL,
    requested_role     TEXT NOT NULL,                     -- 从 ReadOnly 升为 Admin
    duration_minutes   INTEGER NOT NULL,                  -- 60 / 120 / 240
    reason             TEXT NOT NULL,
    ticket_id          TEXT NOT NULL,                     -- 关联 incident / change ticket
    requester          TEXT NOT NULL,
    peer_approver      TEXT,
    status             TEXT NOT NULL DEFAULT 'PENDING',   -- PENDING / APPROVED / ACTIVE / EXPIRED / REVOKED
    requested_at       TEXT NOT NULL DEFAULT (datetime('now')),
    approved_at        TEXT,
    starts_at          TEXT,
    expires_at         TEXT,
    revoked_at         TEXT,
    FOREIGN KEY (identity_id) REFERENCES iam_identities(identity_id)
);

CREATE INDEX IF NOT EXISTS idx_bg_status ON break_glass_sessions(status);
CREATE INDEX IF NOT EXISTS idx_bg_expires ON break_glass_sessions(expires_at);

-- ============================================
-- Audit trail
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
