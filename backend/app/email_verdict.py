"""Rule-based verdict for the Email Domain Checker. Unlike verdict.py (which
layers overrides on top of an ML model's prediction), there is no model
here -- no labeled training set of "phishing sender domain" vs "legitimate
sender domain" exists, so inventing one would be pretending to a rigor this
doesn't have. Everything below is a transparent, tunable rule cascade
instead: a few near-certain cases (ground-truth blocklist hits, an exact
known-brand domain, a typosquat lookalike) short-circuit to a confident
call, and everything else falls through to a capped point-based scorer.

`confidence` here is a rule-tally-derived number, not a calibrated
probability the way the URL checker's model confidence is -- callers
(the API response, the frontend) must present it as a "risk score", never
imply ML-level rigor it doesn't have.

Kept as its own module rather than folded into verdict.py: that module's
own docstring documents it as tightly coupled to app.model.predict's
`Prediction` type, and mixing an unrelated rule-only resolver in would blur
that single responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings

# None | "known_brand_domain" | "confirmed_threat" | "virustotal_flagged"
# | "typosquat_lookalike"
EmailOverrideReason = str


@dataclass(frozen=True)
class EmailVerdict:
    verdict: str  # "safe" | "phishing"
    confidence: float
    low_confidence: bool
    override_reason: EmailOverrideReason | None
    score: int  # raw 0-100 point tally that produced this verdict, for UI/debugging


def resolve_email_verdict(
    *,
    is_exact_brand: bool,
    typosquat_matched: bool,
    confirmed_threat: bool | None,
    virustotal_malicious_count: int | None,
    dns_resolves: bool,
    mx_present: bool | None,
    spf_present: bool | None,
    dmarc_present: bool | None,
    domain_age_days: int | None,
    popularity_rank: int | None,
    has_valid_https: bool,
) -> EmailVerdict:
    # Ground truth outranks the brand allowlist: a compromised real brand
    # domain (e.g. a hijacked subdomain actively serving phishing content)
    # must still be flagged, not waved through just for being on the list.
    if confirmed_threat:
        return EmailVerdict(
            verdict="phishing", confidence=0.99, low_confidence=False,
            override_reason="confirmed_threat", score=100,
        )

    if (
        virustotal_malicious_count is not None
        and virustotal_malicious_count >= settings.virustotal_malicious_threshold
    ):
        return EmailVerdict(
            verdict="phishing", confidence=0.99, low_confidence=False,
            override_reason="virustotal_flagged", score=100,
        )

    if is_exact_brand:
        return EmailVerdict(
            verdict="safe", confidence=0.95, low_confidence=False,
            override_reason="known_brand_domain", score=0,
        )

    if typosquat_matched:
        return EmailVerdict(
            verdict="phishing", confidence=0.9, low_confidence=False,
            override_reason="typosquat_lookalike", score=90,
        )

    score = 0
    if dns_resolves is False:
        score += 30
    # mx_present is False (not None): a domain that resolves but confirms
    # zero MX records is a real flag, but send-only relay domains
    # legitimately exist -- this alone must never be decisive, only ever
    # one contributor among several in the capped tally below.
    if mx_present is False:
        score += 25
    if spf_present is False:
        score += 15
    if dmarc_present is False:
        score += 15
    if domain_age_days is None or domain_age_days < settings.email_min_domain_age_days:
        score += 20
    if popularity_rank is None:
        score += 10
    if not has_valid_https:
        score += 5
    score = min(score, 100)

    threshold = settings.email_phishing_score_threshold
    margin = settings.email_low_confidence_margin
    verdict = "phishing" if score >= threshold else "safe"
    low_confidence = abs(score - threshold) <= margin
    # Confidence scaled from the tally's distance past the threshold, not
    # the raw score itself -- a domain scoring exactly at the threshold
    # should read as ~50/50, not as confident in whichever direction it
    # nominally fell.
    confidence = 0.5 + min(abs(score - threshold), 50) / 100

    return EmailVerdict(
        verdict=verdict, confidence=confidence, low_confidence=low_confidence,
        override_reason=None, score=score,
    )
