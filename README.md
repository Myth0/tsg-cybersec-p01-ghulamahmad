# Personal Security Audit & Password Tool

**Author:** Ghulam Ahmad
**Project:** TSG Cyber Security Internship — Project 01

A personal security audit toolkit consisting of a password strength checker (with live breach-exposure checking) and a structured audit process covering common personal security control areas.

---

## Contents

## Usage

```bash
# Interactive mode (password input is hidden, never echoed to screen)
python3 password_checker.py

# Direct mode (not recommended for real passwords — visible in shell history)
python3 password_checker.py --password "yourpassword"

# Skip the online breach check (useful if offline)
python3 password_checker.py --password "yourpassword" --no-hibp
```

Running the test suite:
```bash
python3 -m unittest tests.test_password_checker -v
```

---

## Scoring Logic — Why It Works This Way

Older password-strength guidance required a mix of uppercase, lowercase, digits, and symbols ("complexity rules"). NIST's current guidance, **SP 800-63B, Section 5.1.1**, moved away from this after research showed it produces predictable results (`Password1!`) while pushing users toward frustration and password reuse. Current best practice prioritizes **length**, and screens against **known-compromised passwords** rather than enforcing arbitrary character rules.

This tool's score is built from four independent signals, combined additively with penalties, not a simple average — because a single disqualifying real-world weakness (e.g. a known-breached password) should outweigh a password that merely "looks" complex on paper.

### 1. Length (up to 70 points) — the dominant factor
| Length | Points |
|---|---|
| 0 | 0 (empty) |
| 1–7 | 10 |
| 8–11 | 25 |
| 12–15 | 40 |
| 16–19 | 55 |
| 20+ | 70 |

Longer passwords exponentially increase the search space an attacker must brute-force, which is why this carries the most weight.

### 2. Character Diversity (up to 20 points) — a minor bonus, not a gate
+5 points for each character class present (lowercase, uppercase, digit, symbol), max 20. This exists because diversity does add some entropy — but it is capped low deliberately, since NIST's research shows it is a much weaker predictor of real strength than length. Whitespace is not counted as a "symbol," since a space in a passphrase is a word separator, not added entropy.

### 3. Common / Breached Password Detection (penalty, up to -60)
The password is checked against a 10,000-entry common-password list (source below). Two checks are run:
- **Exact match:** -60 points. This is the single most severe penalty, because these are the first passwords any real attacker or automated tool tries.
- **Common word + trailing digits** (e.g. `password123` → base word `password`): -45 points. This catches the extremely common real-world pattern of appending digits to a known-weak word, which provides almost no real protection.

### 4. Predictable Pattern Detection (penalty, up to -35)
- Repeated character runs (`aaa`, `111`): -10
- Sequential runs (`abcd`, `1234`, and their reverse): -10
- Keyboard-walk patterns (`qwerty`, `asdfgh`): -10
- Leetspeak disguising a *known common word* (`p@ssw0rd` → normalizes to `password`, which is in the common-password list): -15

**Design note on leetspeak detection:** an earlier version of this check flagged *any* character substitution, regardless of whether it disguised a real word. Testing surfaced a false positive: a genuinely strong random password (e.g. `xK9$mQ2vLp&7Rz4Wf`) was incorrectly flagged, simply because it contained digits/symbols that happened to translate under the leet map. The check was corrected to only trigger when the normalized form actually matches a known common password — tying the penalty to real evidence of weakness rather than superficial character overlap. This is covered by two dedicated regression tests (`test_leetspeak_of_known_word_flagged` and `test_leetspeak_of_unknown_word_not_flagged`).

### 5. Live Breach Check — Have I Been Pwned (penalty, up to -70)
The password is checked against the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) using the **k-anonymity model**:

**The full password is never transmitted** — only a 5-character hash prefix, which on its own cannot be reversed to the original password. If found, this is the heaviest penalty in the model (-70), because it is real-world evidence rather than a theoretical weakness.

**Failure handling:** if the API is unreachable (network issue, timeout, rate limit), the tool explicitly reports the check as "unavailable" rather than treating that as a safe result. An API failure must never be silently interpreted as "not breached" — that would be actively misleading.

### Final Score and Rating

| Score | Rating |
|---|---|
| 75–100 | Strong |
| 50–74 | Moderate |
| 25–49 | Weak |
| 0–24 | Very Weak |

Thresholds are set below the ~90-point ceiling achievable before any penalties apply, so that penalties always have meaningful room to affect the rating rather than being absorbed by an already-maxed score.

---

## Data Sources & Licensing

- **Common password list:** [SecLists](https://github.com/danielmiessler/SecLists) — `Passwords/Common-Credentials/10k-most-common.txt`, MIT License. Used under license for common-password matching; redistributed as part of this project per the license terms.
- **Breach data:** [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords), queried live via the k-anonymity model. No data is stored or redistributed from this source — it is queried at runtime only.
- **Scoring methodology reference:** [NIST SP 800-63B, Section 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines, Authentication and Lifecycle Management.

---

## Privacy & Security Notes

- The raw password is never written to disk, logged, or included in any output file.
- The `--password` CLI flag is provided for convenience but is not recommended for real passwords, since command-line arguments can be captured in shell history. The interactive prompt (hidden input via `getpass`) is the safer default.
- Only a 5-character SHA-1 hash prefix is ever sent over the network (HIBP check) — never the password itself, in any form.

---

## Limitations

- This is a heuristic scoring model, not a cryptographic guarantee of crack-resistance.
- The common-password list (10,000 entries) is a sample, not exhaustive.
- HIBP's dataset reflects only breaches it has indexed; a "clean" result does not guarantee a password has never been exposed elsewhere.
- Pattern detection covers common, well-documented attack patterns but cannot catch every possible predictable structure.
