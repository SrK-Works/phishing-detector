"""Minimal Phone Number Checker. Deliberately the thinnest of the three
checkers: unlike a domain, a phone number has no public, authoritative
"who owns this" registry (no WHOIS/DNS equivalent) -- carrier lookup only
reveals the telecom operator that issued the number, never the account
holder, and India's DLT registry only covers registered bulk-SMS headers,
not voice numbers. So this can only validate properties of the number
itself (format, line type, carrier), never confirm brand ownership --
callers (the API response, the frontend) must present it as a lighter
check than the URL/Email checkers, not imply it can identify who a number
actually belongs to.

Fully offline (no network calls): `phonenumbers` ships its own bundled
metadata, so unlike email_checks.py this needs no timeout handling.
"""

from __future__ import annotations

from dataclasses import dataclass

import phonenumbers
import phonenumbers.carrier

# None | "unparseable_number" | "invalid_format" | "premium_rate_number"
PhoneOverrideReason = str


@dataclass(frozen=True)
class PhoneVerdict:
    verdict: str  # "safe" | "phishing"
    confidence: float
    low_confidence: bool
    override_reason: PhoneOverrideReason | None
    e164: str | None
    region_code: str | None
    is_valid: bool
    is_possible: bool
    line_type: str | None  # PhoneNumberType name, e.g. "MOBILE" -- None if unparseable
    carrier_name: str | None  # None/"" if the offline data has no coverage for this range


def check_phone_number(raw: str, default_region: str = "IN") -> PhoneVerdict:
    """`default_region` only applies when `raw` has no leading "+"/explicit
    country code -- a number entered in full international format (e.g.
    "+14155552671") is parsed against its own country regardless of this
    default.
    """
    try:
        parsed = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException:
        return PhoneVerdict(
            verdict="phishing", confidence=0.55, low_confidence=True,
            override_reason="unparseable_number", e164=None, region_code=None,
            is_valid=False, is_possible=False, line_type=None, carrier_name=None,
        )

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    region_code = phonenumbers.region_code_for_number(parsed)
    line_type = phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(parsed))
    carrier_name = phonenumbers.carrier.name_for_number(parsed, "en") or None

    if not is_valid:
        return PhoneVerdict(
            verdict="phishing", confidence=0.6, low_confidence=True,
            override_reason="invalid_format", e164=e164, region_code=region_code,
            is_valid=False, is_possible=is_possible, line_type=line_type,
            carrier_name=carrier_name,
        )

    if line_type == "PREMIUM_RATE":
        return PhoneVerdict(
            verdict="phishing", confidence=0.55, low_confidence=True,
            override_reason="premium_rate_number", e164=e164, region_code=region_code,
            is_valid=True, is_possible=is_possible, line_type=line_type,
            carrier_name=carrier_name,
        )

    # VOIP is deliberately NOT scored/flagged here -- it's legitimately
    # common (many real businesses use VOIP), so treating it as a red flag
    # would just produce noise. The frontend surfaces it as an
    # informational-only badge instead.
    return PhoneVerdict(
        verdict="safe", confidence=0.5, low_confidence=False,
        override_reason=None, e164=e164, region_code=region_code,
        is_valid=True, is_possible=is_possible, line_type=line_type,
        carrier_name=carrier_name,
    )
