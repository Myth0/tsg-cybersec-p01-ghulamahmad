# Personal Security Audit Report

**Prepared by:** Ghulam Ahmad
**Audit Date:** September 2026
**Scope:** Personal digital accounts and devices (email, social media, browser, mobile device, laptop, backups)
**Reference:** TSG Cyber Security Internship — Project 01

---

## 1. Executive Summary

This report presents the findings of a self-conducted personal security audit, covering authentication practices, password hygiene, application permissions, data backup integrity, and device physical security. The audit identified **5 findings** requiring remediation and **2 verified controls** already operating effectively. The highest-risk finding is password reuse across multiple accounts, compounded by inconsistent two-factor authentication coverage. No critical or actively-exploited issues were identified; all findings represent exposure that increases risk over time rather than an active compromise.

Overall posture at the time of this audit: **Moderate risk**, with a clear and achievable path to Low risk through the remediation plan in Section 6.

---

## 2. Scope and Methodology

The audit covered six control areas, selected to align with common real-world attack vectors against individual users: two-factor authentication, password reuse, browser extensions, application permissions, backup integrity, and device locks.

Each control area was assessed through direct inspection of account settings, device configuration, and a supporting Python-based password strength analysis tool built for this engagement (see Section 7). Findings are risk-rated using a Likelihood × Impact model (Section 4), consistent with standard industry risk-assessment practice. No real account credentials, breach data, or personally identifying account details are included in this report, in line with responsible disclosure practice for a document intended to be shared externally.

**Limitations:** This audit is self-reported and reflects a point-in-time assessment. It does not include penetration testing, does not have visibility into server-side security controls of third-party services, and breach-database checks (Have I Been Pwned) are limited to what that specific dataset has indexed — absence of a match does not guarantee a password has never been exposed elsewhere.

---

## 3. Password Strength Tool — Methodology Summary

A companion Python tool (`password_checker.py`) was developed to support this audit. Its scoring approach is based on NIST SP 800-63B guidance, which found that traditional complexity rules (mandatory uppercase/number/symbol) are weaker predictors of real-world crackability than password length, and that screening against known-breached and common passwords is more effective than arbitrary composition rules.

The tool scores on: length (dominant factor), character diversity (minor factor), exact and near-match common-password detection, predictable pattern detection (sequences, keyboard walks, repeated characters, leetspeak disguising known weak words), and live breach-exposure checking against the Have I Been Pwned database using the k-anonymity model — the full password is never transmitted, only a 5-character hash-prefix. Full methodology and worked examples are documented in the project README.

---

## 4. Risk Rating Methodology

Findings are rated using a **Likelihood × Impact** model:

| | Impact: Low | Impact: Medium | Impact: High |
|---|---|---|---|
| **Likelihood: Low** | Low | Low | Medium |
| **Likelihood: Medium** | Low | Medium | High |
| **Likelihood: High** | Medium | High | High |

**Likelihood** reflects how realistically the weakness could be exploited given known attacker behavior (e.g., automated credential-stuffing against reused passwords is high-likelihood; an attack requiring physical device theft is lower-likelihood). **Impact** reflects the consequence if exploited, including cascading effects (e.g., email compromise typically enables recovery of many other accounts).

---

## 5. Findings

### F-01: Password Reuse Across Multiple Accounts
- **Risk Rating:** High (Likelihood: High, Impact: High)
- **Description:** The same or similar passwords are currently used across multiple personal accounts.
- **Why it matters:** Credential-stuffing is one of the most common and fully-automated attack methods in active use. When one service is breached, attackers immediately test the exposed credentials against other popular services. Reuse turns a single leaked password into a master key for an entire digital identity.
- **Evidence:** Self-reported during audit; confirmed no password manager is currently in use.

### F-02: Inconsistent Two-Factor Authentication Coverage
- **Risk Rating:** High (Likelihood: Medium, Impact: High)
- **Description:** 2FA is enabled on some accounts but not all.
- **Why it matters:** 2FA is the primary control that prevents a leaked or guessed password from resulting in account takeover. Accounts without it are one password disclosure away from full compromise, and this risk directly compounds F-01 — accounts most likely to be affected by reuse are frequently the same ones without a second authentication factor.
- **Evidence:** Self-reported during audit review of account security settings.

### F-03: Unreviewed / Excessive Application Permissions
- **Risk Rating:** Medium (Likelihood: Low, Impact: Medium)
- **Description:** Review of connected third-party applications and OAuth permissions identified access grants that are broader than necessary or no longer in active use.
- **Why it matters:** Each connected application with standing access represents an additional party that could be compromised or could misuse data, independent of the user's own account security.
- **Evidence:** Direct review of connected-app permission listing during audit.

### F-04: Backup Integrity Not Verified
- **Risk Rating:** Medium (Likelihood: Low, Impact: High)
- **Description:** Backups exist but have not been tested to confirm successful restoration.
- **Why it matters:** An untested backup provides false confidence. Backup failures are frequently only discovered at the point of actual data loss, when it is too late to correct — the value of a backup is only proven by a successful restore.
- **Evidence:** Self-reported; no restore test has been performed.

### F-05: Auto-Lock Timeout and Disk Encryption Unverified
- **Risk Rating:** Medium (Likelihood: Low-Medium, Impact: Medium)
- **Description:** Screen locks are enabled on both phone and laptop (a positive control), but auto-lock timeout duration and full-disk encryption status have not been formally confirmed.
- **Why it matters:** A screen lock with a long timeout window, or a device without disk encryption, leaves a materially larger exposure window if the device is lost, stolen, or left unattended.
- **Evidence:** Screen locks confirmed present; timeout and encryption status pending verification.

---

## 6. Verified Controls (No Finding)

| Control | Result |
|---|---|
| Browser extension review | All installed extensions reviewed; none identified as suspicious or from unverified sources |
| Basic device screen locks | Confirmed enabled on both primary phone and laptop |

These are included to reflect an honest, balanced audit — not every control area produced a finding, and existing effective controls should be recognized alongside gaps.

---

## 7. Before / After Remediation Table

| Finding | Risk (Before) | Remediation Step | Status | Risk (After, once applied) |
|---|---|---|---|---|
| F-01 | High | Adopt a password manager; set a unique password on the primary email account first, then highest-value accounts | Planned | Low |
| F-02 | High | Enable 2FA (app-based, not SMS where possible) on all remaining accounts, starting with email and financial accounts | Planned | Low |
| F-03 | Medium | Revoke unused/unnecessary third-party app connections; review remaining permissions for least-privilege | Planned | Low |
| F-04 | Medium | Perform a test restore from the existing backup to confirm integrity | Planned | Low |
| F-05 | Medium | Confirm and, if needed, shorten auto-lock timeout to under 5 minutes; confirm full-disk encryption status and enable if not already active | Planned | Low |

*Once each item is applied in practice, its status will be updated to "Remediated" and the account/device re-checked to confirm the risk reduction reflected above is accurate, not assumed.*

---

## 8. Recommendations Summary

1. Prioritize F-01 and F-02 first — they are both High risk and mutually reinforcing; closing them materially reduces overall exposure.
2. Adopt a password manager as the single highest-leverage change available — it resolves reuse and makes strong unique passwords practical to maintain.
3. Treat backup and device-lock verification (F-04, F-05) as low-effort, high-value checks — both can typically be confirmed in minutes.
4. Re-run this audit periodically (e.g. every 6 months) rather than treating it as a one-time exercise, since account settings and installed applications change over time.

---

## 9. Limitations

This is a self-reported personal audit, not an independent third-party assessment or penetration test. Findings reflect the state of accounts and devices at the time of review and may change. The Have I Been Pwned check reflects only breaches that service has indexed; a "clean" result is not a guarantee of safety. Risk ratings represent a structured, reasoned estimate, not a precise mathematical guarantee.
