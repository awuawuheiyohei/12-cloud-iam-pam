"""Seed 20 IAM identities + 1 UAR campaign + JIT sessions"""
import json
from datetime import date, datetime, timedelta

from .db import get_conn, init_db
from .iam_analyzer import analyze_identity


# ============================================
# 20 Mock IAM Identities
# ============================================
def _make_inline_policies():
    """各类典型 policy"""
    return {
        # 1. Full admin (CRITICAL)
        "AdminFull": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        },
        # 2. iam:* on Resource: * (CRITICAL — privilege escalation)
        "IamFull": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:*"],
                "Resource": "*",
            }],
        },
        # 3. iam:PassRole + lambda:Invoke (HIGH)
        "PassRoleAndInvoke": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:InvokeFunction"],
                "Resource": "*",
            }],
        },
        # 4. Scoped EC2 read (LOW)
        "Ec2ReadOnly": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:Describe*", "ec2:Get*"],
                "Resource": "*",
            }],
        },
        # 5. S3 bucket specific (LOW)
        "S3Scoped": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"],
            }],
        },
        # 6. KMS decrypt (LOW)
        "KmsDecrypt": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey"],
                "Resource": ["arn:aws:kms:us-east-1:123456789012:key/abcd-1234"],
            }],
        },
    }


def _make_identities():
    today = date.today()
    iso = lambda d: d.isoformat()
    keys_active = json.dumps([{"id": "AKIAEXAMPLE1", "status": "Active", "created": "2024-01-01"}])
    keys_rotated = json.dumps([
        {"id": "AKIAEXAMPLE2", "status": "Active", "created": "2024-03-01"},
        {"id": "AKIAEXAMPLE3", "status": "Inactive", "created": "2023-01-01"},
    ])
    keys_none = json.dumps([])
    policies = _make_inline_policies()

    return [
        # 1. Alice — Senior SRE, MFA, active, scoped EC2 + KMS (clean)
        {"identity_id": "IAM-001", "identity_name": "alice@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/alice", "account_id": "111111111111",
         "email": "alice@tripbiz.com", "manager": "manager-sre",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=730)),
         "last_active_at": iso(today - timedelta(days=2)),
         "password_last_set": iso(today - timedelta(days=180)),
         "access_keys": keys_rotated,
         "status": "ACTIVE",
         "attached_policies": json.dumps(["arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"]),
         "inline_policies": json.dumps({}),
         "notes": "SRE on-call"},

        # 2. Bob — DevOps lead, MFA, active, Lambda + PassRole + iam:CreateAccessKey
        {"identity_id": "IAM-002", "identity_name": "bob@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/bob", "account_id": "111111111111",
         "email": "bob@tripbiz.com", "manager": "manager-devops",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=900)),
         "last_active_at": iso(today - timedelta(days=1)),
         "password_last_set": iso(today - timedelta(days=60)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"PassRoleAndInvoke": policies["PassRoleAndInvoke"]}),
         "notes": "DevOps lead — needs PassRole for Lambda deploys"},

        # 3. Carol — Engineer, MFA, active, S3 scoped (clean)
        {"identity_id": "IAM-003", "identity_name": "carol@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/carol", "account_id": "111111111111",
         "email": "carol@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=400)),
         "last_active_at": iso(today - timedelta(days=5)),
         "password_last_set": iso(today - timedelta(days=90)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": "Data engineer"},

        # 4. Dave — Intern left, NO MFA, dormant 180 days
        {"identity_id": "IAM-004", "identity_name": "dave@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/dave", "account_id": "111111111111",
         "email": "dave@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=400)),
         "last_active_at": iso(today - timedelta(days=180)),
         "password_last_set": iso(today - timedelta(days=380)),
         "access_keys": keys_active,
         "status": "INACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"Ec2ReadOnly": policies["Ec2ReadOnly"]}),
         "notes": "Intern departed — needs cleanup"},

        # 5. Eve — Admin from 2020, MFA, but FULL ADMIN (CRITICAL)
        {"identity_id": "IAM-005", "identity_name": "eve.admin@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/eve.admin", "account_id": "111111111111",
         "email": "eve.admin@tripbiz.com", "manager": "CISO",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=1500)),
         "last_active_at": iso(today - timedelta(days=3)),
         "password_last_set": iso(today - timedelta(days=30)),
         "access_keys": keys_rotated,
         "status": "ACTIVE",
         "attached_policies": json.dumps(["arn:aws:iam::aws:policy/AdministratorAccess"]),
         "inline_policies": json.dumps({}),
         "notes": "CTO legacy admin — high blast radius"},

        # 6. Frank — Security Engineer, MFA, iam:* on Resource:* (CRITICAL)
        {"identity_id": "IAM-006", "identity_name": "frank.sec@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/frank.sec", "account_id": "111111111111",
         "email": "frank.sec@tripbiz.com", "manager": "CISO",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=600)),
         "last_active_at": iso(today - timedelta(days=1)),
         "password_last_set": iso(today - timedelta(days=45)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"IamFull": policies["IamFull"]}),
         "notes": "Security engineer — used for IAM investigation"},

        # 7. Grace — Data scientist, NO MFA, active
        {"identity_id": "IAM-007", "identity_name": "grace@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/grace", "account_id": "111111111111",
         "email": "grace@tripbiz.com", "manager": "manager-data",
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=200)),
         "last_active_at": iso(today - timedelta(days=10)),
         "password_last_set": iso(today - timedelta(days=200)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": "Data scientist — needs MFA enforcement"},

        # 8. Henry — Vendor (external), MFA, IAM PassRole only
        {"identity_id": "IAM-008", "identity_name": "henry@vendor-x.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/henry.vendor", "account_id": "111111111111",
         "email": "henry@vendor-x.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=120)),
         "last_active_at": iso(today - timedelta(days=7)),
         "password_last_set": iso(today - timedelta(days=120)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"PassRoleAndInvoke": policies["PassRoleAndInvoke"]}),
         "notes": "Vendor X contractor — expires 90d"},

        # 9. Ivan — Old employee, terminated, never disabled
        {"identity_id": "IAM-009", "identity_name": "ivan.legacy@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/ivan.legacy", "account_id": "111111111111",
         "email": "ivan.legacy@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=1100)),
         "last_active_at": iso(today - timedelta(days=300)),
         "password_last_set": iso(today - timedelta(days=800)),
         "access_keys": keys_rotated,
         "status": "INACTIVE",
         "attached_policies": json.dumps(["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]),
         "inline_policies": json.dumps({}),
         "notes": "Terminated 2025-11 — needs deletion"},

        # 10. Judy — Auditor, MFA, S3 scoped (clean)
        {"identity_id": "IAM-010", "identity_name": "judy@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/judy", "account_id": "111111111111",
         "email": "judy@tripbiz.com", "manager": "CISO",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=180)),
         "last_active_at": iso(today - timedelta(days=4)),
         "password_last_set": iso(today - timedelta(days=60)),
         "access_keys": keys_none,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": "External auditor — read-only"},

        # 11-15: Standard users with various roles
        {"identity_id": "IAM-011", "identity_name": "user-eng-01@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/user-eng-01", "account_id": "111111111111",
         "email": "user-eng-01@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=300)),
         "last_active_at": iso(today - timedelta(days=15)),
         "password_last_set": iso(today - timedelta(days=90)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"Ec2ReadOnly": policies["Ec2ReadOnly"]}),
         "notes": ""},
        {"identity_id": "IAM-012", "identity_name": "user-eng-02@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/user-eng-02", "account_id": "111111111111",
         "email": "user-eng-02@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=200)),
         "last_active_at": iso(today - timedelta(days=8)),
         "password_last_set": iso(today - timedelta(days=90)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"KmsDecrypt": policies["KmsDecrypt"]}),
         "notes": ""},
        {"identity_id": "IAM-013", "identity_name": "user-data-01@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/user-data-01", "account_id": "111111111111",
         "email": "user-data-01@tripbiz.com", "manager": "manager-data",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=250)),
         "last_active_at": iso(today - timedelta(days=20)),
         "password_last_set": iso(today - timedelta(days=80)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": ""},
        {"identity_id": "IAM-014", "identity_name": "user-sec-01@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/user-sec-01", "account_id": "111111111111",
         "email": "user-sec-01@tripbiz.com", "manager": "CISO",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=400)),
         "last_active_at": iso(today - timedelta(days=2)),
         "password_last_set": iso(today - timedelta(days=40)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"Ec2ReadOnly": policies["Ec2ReadOnly"]}),
         "notes": ""},
        {"identity_id": "IAM-015", "identity_name": "user-vendor-01@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/user-vendor-01", "account_id": "111111111111",
         "email": "user-vendor-01@tripbiz.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=60)),
         "last_active_at": iso(today - timedelta(days=3)),
         "password_last_set": iso(today - timedelta(days=60)),
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": "New vendor — 30d review"},

        # 16-17: Roles (cross-account)
        {"identity_id": "IAM-016", "identity_name": "role-data-pipeline", "identity_type": "ROLE",
         "identity_arn": "arn:aws:iam::111111111111:role/data-pipeline", "account_id": "111111111111",
         "email": None, "manager": None,
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=500)),
         "last_active_at": iso(today - timedelta(days=10)),
         "password_last_set": None,
         "access_keys": keys_none,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"Ec2ReadOnly": policies["Ec2ReadOnly"], "S3Scoped": policies["S3Scoped"]}),
         "notes": "ETL role"},
        {"identity_id": "IAM-017", "identity_name": "role-admin-cross-account", "identity_type": "ROLE",
         "identity_arn": "arn:aws:iam::111111111111:role/admin-cross-account", "account_id": "111111111111",
         "email": None, "manager": None,
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=800)),
         "last_active_at": iso(today - timedelta(days=120)),
         "password_last_set": None,
         "access_keys": keys_none,
         "status": "ACTIVE",
         "attached_policies": json.dumps(["arn:aws:iam::aws:policy/AdministratorAccess"]),
         "inline_policies": json.dumps({}),
         "notes": "Cross-account admin — review trust policy"},

        # 18. Vendor expired 200 days ago, MFA, never disabled
        {"identity_id": "IAM-018", "identity_name": "vendor-y@external.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/vendor-y", "account_id": "111111111111",
         "email": "vendor-y@external.com", "manager": "manager-eng",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=600)),
         "last_active_at": iso(today - timedelta(days=200)),
         "password_last_set": iso(today - timedelta(days=400)),
         "access_keys": keys_active,
         "status": "INACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"S3Scoped": policies["S3Scoped"]}),
         "notes": "Vendor contract ended 2026-03"},

        # 19. Service account (CI/CD), no MFA, scoped
        {"identity_id": "IAM-019", "identity_name": "svc-cicd-pipeline", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/svc-cicd", "account_id": "111111111111",
         "email": None, "manager": "manager-devops",
         "mfa_enabled": 0, "created_at": iso(today - timedelta(days=400)),
         "last_active_at": iso(today - timedelta(days=1)),
         "password_last_set": None,
         "access_keys": keys_active,
         "status": "ACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"PassRoleAndInvoke": policies["PassRoleAndInvoke"]}),
         "notes": "Service account — no console access"},

        # 20. Marketing user, MFA, dormant (no recent activity)
        {"identity_id": "IAM-020", "identity_name": "mkt-old@tripbiz.com", "identity_type": "USER",
         "identity_arn": "arn:aws:iam::111111111111:user/mkt-old", "account_id": "111111111111",
         "email": "mkt-old@tripbiz.com", "manager": "manager-mkt",
         "mfa_enabled": 1, "created_at": iso(today - timedelta(days=900)),
         "last_active_at": iso(today - timedelta(days=160)),
         "password_last_set": iso(today - timedelta(days=400)),
         "access_keys": keys_active,
         "status": "INACTIVE",
         "attached_policies": json.dumps([]),
         "inline_policies": json.dumps({"Ec2ReadOnly": policies["Ec2ReadOnly"]}),
         "notes": "Marketing — no recent campaigns"},
    ]


# ============================================
# Seed
# ============================================
def seed_identities(verbose=False):
    init_db()
    conn = get_conn()
    # 先删 FK 依赖方
    conn.execute("DELETE FROM break_glass_sessions")
    conn.execute("DELETE FROM access_review_decisions")
    conn.execute("DELETE FROM access_review_campaigns")
    conn.execute("DELETE FROM iam_risk_findings")
    conn.execute("DELETE FROM iam_identities")
    conn.execute("DELETE FROM audit_trail")

    identities = _make_identities()
    for i in identities:
        conn.execute(
            """INSERT INTO iam_identities
               (identity_id, identity_name, identity_type, identity_arn, account_id, email,
                manager, mfa_enabled, created_at, last_active_at, password_last_set,
                access_keys, status, attached_policies, inline_policies, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (i["identity_id"], i["identity_name"], i["identity_type"], i["identity_arn"], i["account_id"],
             i["email"], i["manager"], i["mfa_enabled"], i["created_at"], i["last_active_at"],
             i["password_last_set"], i["access_keys"], i["status"],
             i["attached_policies"], i["inline_policies"], i["notes"])
        )
    conn.commit()
    if verbose:
        print(f"[+] Seeded {len(identities)} IAM identities")
    return len(identities)


def seed_findings(verbose=False):
    """对每条 identity 跑 analyzer 写 findings"""
    conn = get_conn()
    identities = []
    rows = conn.execute("SELECT * FROM iam_identities").fetchall()
    for r in rows:
        identities.append({k: r[k] for k in r.keys()})

    inserted = 0
    counter = [0]
    for ident in identities:
        findings = analyze_identity(ident)
        for f in findings:
            counter[0] += 1
            fid = f"F-{counter[0]:04d}"
            conn.execute(
                """INSERT INTO iam_risk_findings
                   (finding_id, identity_id, identity_name, risk_type, severity, details,
                    evidence, recommended_action, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
                (fid, f["identity_id"], f["identity_name"], f["risk_type"], f["severity"],
                 f["details"], f["evidence"], f["recommended_action"])
            )
            inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} risk findings (analyzed {len(identities)} identities)")
    return inserted


def seed_uar_campaign(verbose=False):
    """Seed Q3 2026 UAR campaign + 全部 manager 决策 PENDING"""
    conn = get_conn()
    today = date.today()
    quarter = f"{today.year}-Q{(today.month - 1) // 3 + 1}"
    campaign_id = f"UAR-{quarter}"

    conn.execute("DELETE FROM access_review_decisions WHERE campaign_id=?", (campaign_id,))
    conn.execute("DELETE FROM access_review_campaigns WHERE campaign_id=?", (campaign_id,))
    conn.execute(
        """INSERT INTO access_review_campaigns (campaign_id, campaign_name, quarter, due_date, status, description)
           VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?)""",
        (campaign_id, f"Quarterly Access Review {quarter}", quarter,
         (today + timedelta(days=30)).isoformat(),
         f"Quarterly UAR — managers must approve/revoke/modify direct reports' access by due date.")
    )

    # 全部 active USER 给其 manager 加 PENDING decision
    users = conn.execute("SELECT identity_id, identity_name, manager FROM iam_identities WHERE identity_type='USER' AND manager IS NOT NULL").fetchall()
    n = 0
    for u in users:
        n += 1
        did = f"UAR-DEC-{n:04d}"
        conn.execute(
            """INSERT INTO access_review_decisions (decision_id, campaign_id, identity_id, identity_name, manager, decision, justification)
               VALUES (?, ?, ?, ?, ?, 'PENDING', NULL)""",
            (did, campaign_id, u["identity_id"], u["identity_name"], u["manager"])
        )
    conn.commit()
    if verbose:
        print(f"[+] Seeded campaign {campaign_id} with {n} pending decisions")
    return {"campaign_id": campaign_id, "decisions": n}


def seed_break_glass(verbose=False):
    """Seed 2 个 JIT session — 1 ACTIVE / 1 EXPIRED"""
    conn = get_conn()
    now = datetime.now()
    samples = [
        {
            "bg_id": "BG-001",
            "identity_id": "IAM-002",  # Bob
            "identity_name": "bob@tripbiz.com",
            "requested_role": "arn:aws:iam::111111111111:role/ProductionLambdaDeploy",
            "duration_minutes": 120,
            "reason": "Production Lambda deployment for incident INC-2026-0421 (DDoS mitigation)",
            "ticket_id": "INC-2026-0421",
            "requester": "bob@tripbiz.com",
            "peer_approver": "alice@tripbiz.com",
            "status": "ACTIVE",
            "starts_at": (now - timedelta(minutes=30)).isoformat(),
            "expires_at": (now + timedelta(minutes=90)).isoformat(),
            "approved_at": (now - timedelta(minutes=35)).isoformat(),
        },
        {
            "bg_id": "BG-002",
            "identity_id": "IAM-006",  # Frank
            "identity_name": "frank.sec@tripbiz.com",
            "requested_role": "arn:aws:iam::111111111111:role/SecurityIncidentResponse",
            "duration_minutes": 60,
            "reason": "Security investigation on suspected credential leak",
            "ticket_id": "SEC-2026-0099",
            "requester": "frank.sec@tripbiz.com",
            "peer_approver": "judy@tripbiz.com",
            "status": "EXPIRED",
            "starts_at": (now - timedelta(hours=2)).isoformat(),
            "expires_at": (now - timedelta(hours=1)).isoformat(),
            "approved_at": (now - timedelta(hours=2, minutes=5)).isoformat(),
            "revoked_at": (now - timedelta(hours=1, minutes=2)).isoformat(),
        },
    ]
    inserted = 0
    for s in samples:
        conn.execute(
            """INSERT INTO break_glass_sessions
               (bg_id, identity_id, identity_name, requested_role, duration_minutes,
                reason, ticket_id, requester, peer_approver, status,
                requested_at, approved_at, starts_at, expires_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (s["bg_id"], s["identity_id"], s["identity_name"], s["requested_role"], s["duration_minutes"],
             s["reason"], s["ticket_id"], s["requester"], s["peer_approver"], s["status"],
             (now - timedelta(minutes=45)).isoformat(), s["approved_at"],
             s["starts_at"], s["expires_at"], s.get("revoked_at"))
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} break-glass sessions")
    return inserted


def seed_all(verbose=False):
    n_i = seed_identities(verbose=verbose)
    n_f = seed_findings(verbose=verbose)
    n_u = seed_uar_campaign(verbose=verbose)
    n_b = seed_break_glass(verbose=verbose)
    return {"identities": n_i, "findings": n_f, "uar_decisions": n_u["decisions"], "break_glass": n_b}


if __name__ == "__main__":
    print(seed_all(verbose=True))
