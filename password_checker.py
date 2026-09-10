#!/usr/bin/env python3
"""
Password Strength Checker
Ghulam Ahmad  - Project 02


Scores password strength based on NIST SP 800-63B guidance: length is
the dominant factor, character diversity is a minor bonus, and known
common/breached passwords and predictable patterns are penalized
heavily, since those are the failure modes real attackers exploit.

SECURITY NOTE: This script never writes, logs, or prints the raw
password to any file. It only exists in memory for the duration of
the check.

Usage:
    python3 password_checker.py
    python3 password_checker.py --password "mypassword123"
"""

import argparse
import getpass
import hashlib
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
})

# ANSI colors for terminal output (no external dependencies needed)
class C:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def load_common_passwords():
    """Load the common password list into a set for fast lookups."""
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        return set(line.strip().lower() for line in f if line.strip())


def check_length(password):
    """
    Length is the dominant factor per NIST 800-63B Section 5.1.1.
    Max points: 70. Tiers chosen so that 20+ characters (a solid
    passphrase) reaches the top tier on length alone.
    """
    length = len(password)
    if length == 0:
        return 0, "Password is empty."
    if length < 8:
        return 10, f"Only {length} characters — below the 8-character practical minimum."
    if length < 12:
        return 25, f"{length} characters — meets the bare minimum but short by current standards."
    if length < 16:
        return 40, f"{length} characters — solid length."
    if length < 20:
        return 55, f"{length} characters — strong length."
    return 70, f"{length} characters — excellent length, the single strongest factor here."


def check_diversity(password):
    """
    Minor bonus for character class diversity — not a hard gate.
    Whitespace is deliberately excluded from the 'symbol' class:
    a space in a passphrase is a word separator, not entropy from
    symbol variety, and shouldn't be credited as if it were.
    Max points: 20.
    """
    classes = 0
    details = []
    if re.search(r"[a-z]", password):
        classes += 1
        details.append("lowercase")
    if re.search(r"[A-Z]", password):
        classes += 1
        details.append("uppercase")
    if re.search(r"[0-9]", password):
        classes += 1
        details.append("digits")
    if re.search(r"[^a-zA-Z0-9\s]", password):
        classes += 1
        details.append("symbols")

    points = classes * 5  # max 20
    reason = f"Uses {classes}/4 character types ({', '.join(details) if details else 'none'})."
    return points, reason


def check_common_password(password, common_set):
    """
    Checks two things, both severe penalties since these are the
    patterns real attackers try first:
      1. Exact match against a known common/breached password.
      2. The password minus trailing digits matches a common password
         (e.g. 'password123' -> 'password') — the single most common
         real-world weak-password pattern.
    """
    lower = password.lower()
    if lower in common_set:
        return -60, "Matches a known common/breached password exactly — the weakest possible case."

    stripped = re.sub(r"\d+$", "", lower)
    if stripped and stripped != lower and stripped in common_set:
        return -45, (
            f"Base word ('{stripped}') is a known common password with digits appended — "
            "a predictable pattern attackers check first, not real added security."
        )
    return 0, None


def check_patterns(password, common_set=None):
    """
    Detects sequences, keyboard walks, repeats, and leetspeak that
    disguises a real known-common word.

    Leetspeak is only flagged when the normalized (de-leeted) form
    actually matches a known common password -- not just because the
    password happens to contain a digit or symbol. A random string
    like 'xK9$mQ2vLp' translates differently under the leet map too,
    but it isn't disguising anything, so it should not be penalized
    as if it were.
    """
    penalty = 0
    reasons = []
    lower = password.lower()
    common_set = common_set or set()

    if re.search(r"(.)\1{2,}", lower):
        penalty -= 10
        reasons.append("Contains a repeated character run (e.g. 'aaa', '111').")

    sequences = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(len(lower) - 3):
        chunk = lower[i:i + 4]
        if chunk in sequences or chunk in sequences[::-1]:
            penalty -= 10
            reasons.append(f"Contains a predictable sequence ('{chunk}').")
            break

    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in lower:
                penalty -= 10
                reasons.append(f"Contains a keyboard-walk pattern ('{chunk}').")
                break

    normalized = lower.translate(LEET_MAP)
    if normalized != lower and normalized in common_set:
        reasons.append(
            f"Uses simple character substitution to disguise a known common password "
            f"(normalizes to '{normalized}') — a well-known evasion pattern that does not "
            "add real strength."
        )
        penalty -= 15

    return penalty, reasons


def check_hibp_breach(password, timeout=5):
    """
    Checks the password against the Have I Been Pwned Pwned Passwords
    API using the k-anonymity model: only a 5-character SHA-1 hash
    prefix is ever sent over the network. The full password never
    leaves this machine.

    Returns a tuple: (status, breach_count, message)
      status: "breached" | "clean" | "unavailable"
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tsg-cybersec-p01-password-checker"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return "unavailable", 0, (
            "Could not reach the breach-check service (network issue or timeout). "
            "This does NOT mean the password is safe — it means this check could not run."
        )

    for line in body.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            count = int(count)
            return "breached", count, (
                f"Found in {count:,} known data breaches. This password must be changed "
                "immediately everywhere it is used."
            )

    return "clean", 0, "Not found in the HIBP breach database (does not guarantee safety, only that this specific dataset has no record)."


def calculate_score(password, common_set, hibp_result=None):
    """
    Combines all signals into a 0-100 score with full reasoning attached.

    Design note: penalties are SUBTRACTED from a base score rather than
    averaged in, because a single disqualifying real-world weakness
    (a known-breached password, a keyboard walk) should tank the score
    even if length/diversity look fine on paper. A password isn't safe
    because it's long AND happens to be 'Password1234' in disguise.
    """
    if not password:
        return {"score": 0, "rating": "Invalid", "reasons": ["Password is empty — cannot be evaluated."]}

    length_points, length_reason = check_length(password)
    diversity_points, diversity_reason = check_diversity(password)
    common_penalty, common_reason = check_common_password(password, common_set)
    pattern_penalty, pattern_reasons = check_patterns(password, common_set)

    hibp_penalty = 0
    hibp_reason = None
    if hibp_result is not None:
        status, count, message = hibp_result
        if status == "breached":
            hibp_penalty = -70
            hibp_reason = f"HIBP: {message}"
        elif status == "unavailable":
            hibp_reason = f"HIBP: {message}"

    raw_score = length_points + diversity_points + common_penalty + pattern_penalty + hibp_penalty
    score = max(0, min(100, raw_score))

    # Thresholds set relative to the ~90-point max achievable before
    # penalties, so "Strong" is reachable for genuinely strong passwords
    # but leaves headroom below the ceiling for penalty deductions.
    if score >= 75:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    elif score >= 25:
        rating = "Weak"
    else:
        rating = "Very Weak"

    reasons = [length_reason, diversity_reason]
    if common_reason:
        reasons.append(common_reason)
    reasons.extend(pattern_reasons)
    if hibp_reason:
        reasons.append(hibp_reason)

    return {"score": score, "rating": rating, "reasons": reasons}


def get_feedback(password, result):
    """Specific, actionable feedback — not just a score."""
    feedback = []
    if len(password) < 12:
        feedback.append("Increase length to at least 12 characters, ideally 16+ or use a passphrase.")
    if any("common" in r.lower() for r in result["reasons"]):
        feedback.append("This password (or its base word) is known to attackers — change it immediately, everywhere it's reused.")
    if any("HIBP:" in r and "found in" in r.lower() for r in result["reasons"]):
        feedback.append("This exact password has appeared in real breaches — stop using it anywhere, today.")
    if any(("sequence" in r or "keyboard-walk" in r or "repeated" in r) for r in result["reasons"]):
        feedback.append("Avoid sequences, repeated characters, and keyboard patterns.")
    if any("substitution" in r for r in result["reasons"]):
        feedback.append("Simple substitutions (@ for a, 0 for o) don't fool modern cracking tools — avoid relying on them.")
    if not feedback:
        feedback.append("Consider a passphrase of 4-5 random unrelated words for even stronger, more memorable security.")
    return feedback


def rating_color(rating):
    return {
        "Strong": C.GREEN,
        "Moderate": C.YELLOW,
        "Weak": C.ORANGE,
        "Very Weak": C.RED,
        "Invalid": C.RED,
    }.get(rating, C.RESET)


def score_bar(score, width=20):
    """Renders a simple colored block-bar for the score, no dependencies."""
    filled = round((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar


def print_report(result, feedback):
    color = rating_color(result["rating"])
    bar = score_bar(result["score"])
    width = 56

    print("\n" + C.BOLD + C.CYAN + "┏" + "━" * width + "┓" + C.RESET)
    print(C.BOLD + C.CYAN + "┃" + C.RESET + f"{'PASSWORD STRENGTH REPORT':^{width}}" + C.BOLD + C.CYAN + "┃" + C.RESET)
    print(C.BOLD + C.CYAN + "┗" + "━" * width + "┛" + C.RESET)

    print(f"\n  {C.BOLD}Score:{C.RESET}  {color}{bar}{C.RESET}  {C.BOLD}{result['score']}/100{C.RESET}")
    print(f"  {C.BOLD}Rating:{C.RESET} {color}{C.BOLD}{result['rating']}{C.RESET}")

    print(f"\n  {C.BOLD}Reasoning:{C.RESET}")
    for r in result["reasons"]:
        print(f"    {C.DIM}-{C.RESET} {r}")

    print(f"\n  {C.BOLD}Recommendations:{C.RESET}")
    for f in feedback:
        print(f"    {C.GREEN}✓{C.RESET} {f}")

    print(C.CYAN + "\n" + "─" * (width + 2) + C.RESET + "\n")


def main():
    parser = argparse.ArgumentParser(description="Password strength checker (NIST SP 800-63B informed).")
    parser.add_argument(
        "--password",
        help="Password to check directly. Prefer the hidden interactive prompt for real passwords "
             "(this flag can leak into shell history).",
    )
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="Skip the online breach check (useful if offline).",
    )
    args = parser.parse_args()

    password = args.password if args.password else getpass.getpass("Enter password to check (input hidden): ")

    common_set = load_common_passwords()

    hibp_result = None
    if not args.no_hibp and password:
        print("Checking against HIBP breach database (k-anonymity — only a hash prefix is sent)...")
        hibp_result = check_hibp_breach(password)

    result = calculate_score(password, common_set, hibp_result)
    feedback = get_feedback(password, result)
    print_report(result, feedback)


if __name__ == "__main__":
    main()
