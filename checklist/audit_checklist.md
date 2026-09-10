# Personal Security Audit Checklist

**Auditor:** Ghulam Ahmad
**Scope:** Personal accounts and devices (generically described, no identifying account details per submission requirements)
**Methodology:** Self-assessment against each control area below. Each item records the current state, whether it represents a finding, and links to the corresponding finding ID in the Security Audit Report.

---

## 1. Two-Factor Authentication (2FA)

| # | Item | Status | Finding |
|---|------|--------|---------|
| 1.1 | 2FA enabled across all major accounts | Partial — enabled on some accounts, not all | F-02 |
| 1.2 | 2FA method is app-based rather than SMS-only where enabled | To be confirmed per account | — |
| 1.3 | Backup/recovery codes stored securely | To be confirmed | — |

## 2. Password Reuse

| # | Item | Status | Finding |
|---|------|--------|---------|
| 2.1 | Password manager in use | No | F-01 |
| 2.2 | Passwords are unique across accounts | No — same/similar passwords reused across multiple accounts | F-01 |

## 3. Browser Extensions

| # | Item | Status | Finding |
|---|------|--------|---------|
| 3.1 | Extensions reviewed for legitimacy | Yes — reviewed, nothing suspicious found | None (verified control) |
| 3.2 | All extensions from verified sources | Yes, based on review | None (verified control) |

## 4. Application Permissions

| # | Item | Status | Finding |
|---|------|--------|---------|
| 4.1 | App/OAuth permissions reviewed | Reviewed — some permissions identified as excessive/unnecessary | F-03 |
| 4.2 | Unnecessary permissions revoked | Not yet — pending remediation | F-03 |

## 5. Backups

| # | Item | Status | Finding |
|---|------|--------|---------|
| 5.1 | Backup exists | Yes | None |
| 5.2 | Backup restore has been tested | No — not yet verified | F-04 |

## 6. Device Locks

| # | Item | Status | Finding |
|---|------|--------|---------|
| 6.1 | Phone screen lock enabled | Yes | None (verified control) |
| 6.2 | Laptop screen lock enabled | Yes | None (verified control) |
| 6.3 | Auto-lock timeout confirmed short (under 5 min) | Not yet verified | F-05 |
| 6.4 | Full-disk encryption confirmed enabled | Not yet verified | F-05 |

---

## Summary

| Category | Findings |
|---|---|
| Two-Factor Authentication | 1 (F-02) |
| Password Reuse | 1 (F-01) |
| Browser Extensions | 0 — verified control |
| Application Permissions | 1 (F-03) |
| Backups | 1 (F-04) |
| Device Locks | 1 (F-05) |
| **Total findings** | **5** |
| **Verified controls (no finding)** | **2** |

*Full reasoning, risk ratings, and remediation for each finding are documented in the Security Audit Report.*
