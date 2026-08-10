"""Combines the ML model's statistical verdict with independent,
rule-based overrides that outrank it, highest authority first:

1. Google Safe Browsing confirmed match, OR VirusTotal reporting at least
   `virustotal_malicious_threshold` security vendors flagging the URL --
   ground truth, not a guess, so either one wins regardless of what the
   model or popularity say. Requiring multiple VirusTotal engines to agree
   (rather than treating any single flag as confirmation) filters out the
   single-overzealous-heuristic noise that's common in VT's ecosystem.
2. A close lookalike of a known brand domain (app.features.lexical's
   typosquat check) -- deliberately conservative (ratio-gated, exact
   brand matches excluded), so when it does fire it's a strong enough
   phishing indicator to drive the verdict itself. Without this, the UI
   could show a red "this looks like a lookalike" banner right next to a
   confident green "safe" badge, which is exactly what happened before
   this rule existed: paypa1.com scored 95.7% legit from the model alone.
3. Tranco popularity -- a domain among the world's most-visited sites is
   strong evidence of legitimacy that doesn't depend on our own
   WHOIS/content signals (which can fail or get blocked by the site
   itself), so it can override a shaky/borderline model call. A real
   typosquat domain is essentially never itself globally popular, so this
   rarely conflicts with rule 2 in practice -- but rule 2 still takes
   priority since a compromised/newly-popular lookalike is exactly the
   case worth erring cautious on.
4. DNS doesn't resolve at all -- forces "uncertain" regardless of which
   way the model leans, because there is no live site to have verified
   anything about. This is a stronger, bidirectional version of rule 6
   below: a track-record-less domain that *does* resolve could still be a
   genuine same-day launch with a real, inspectable site; a domain that
   doesn't resolve at all has zero verifiable presence -- calling it
   confidently "safe" is just as unsupportable as calling it confidently
   "phishing" (caught live: a nonexistent domain scored 87% "safe" from
   the model alone, purely because training data rarely includes examples
   of either class that fail to resolve -- see DATASET.md bug #8).
5. Tranco popularity -- a domain among the world's most-visited sites is
   strong evidence of legitimacy that doesn't depend on our own
   WHOIS/content signals (which can fail or get blocked by the site
   itself), so it can override a shaky/borderline model call. A real
   typosquat domain is essentially never itself globally popular, so this
   rarely conflicts with rule 2 in practice -- but rule 2 still takes
   priority since a compromised/newly-popular lookalike is exactly the
   case worth erring cautious on.
6. No track record at all (no WHOIS creation date AND not in Tranco) --
   softens a confident *phishing* call to "uncertain" rather than letting
   it stand. A brand-new domain looks statistically similar whether it's a
   genuine same-day launch (a new indie app, often hosted on a shared
   builder platform like Lovable/Vercel/Netlify -- itself a dual-use
   pattern real phishing kits also use, see DATASET.md bug #4) or a
   same-day phishing page: neither has the age/popularity/reputation
   history our strongest signals depend on, and nobody -- including Safe
   Browsing, which hasn't crawled it yet either -- can vouch for a URL
   that young. Confidently calling that "phishing" claims certainty the
   underlying signal can't support; "uncertain" is the honest answer for
   *both* the good-faith and bad-faith case, not just the one that
   complains about it. Deliberately one-directional: doesn't touch a
   track-record-less domain the model already calls "safe" -- there's no
   equivalent reason to manufacture doubt about a call that isn't a false
   alarm.
7. Otherwise, the model's own verdict/confidence stands, including its
   "uncertain" (low_confidence) framing when the underlying signal is
   thin.

Kept as a separate module (rather than inline in routes.py) because this
is exactly the kind of decision logic worth unit testing in isolation from
the FastAPI request cycle.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings
from app.model.predict import Prediction

# None | "confirmed_threat" | "virustotal_flagged" | "typosquat_lookalike"
# | "domain_unreachable" | "popular_domain" | "no_track_record"
OverrideReason = str


@dataclass(frozen=True)
class Verdict:
    verdict: str  # "safe" | "phishing"
    confidence: float
    low_confidence: bool
    override_reason: OverrideReason | None


def resolve_verdict(
    prediction: Prediction,
    *,
    popularity_rank: int | None,
    confirmed_threat: bool | None,
    virustotal_malicious_count: int | None,
    typosquat_target: str | None,
    whois_missing: bool,
    dns_resolves: bool | None,
) -> Verdict:
    if confirmed_threat:
        return Verdict(
            verdict="phishing", confidence=0.99, low_confidence=False,
            override_reason="confirmed_threat",
        )

    if (
        virustotal_malicious_count is not None
        and virustotal_malicious_count >= settings.virustotal_malicious_threshold
    ):
        return Verdict(
            verdict="phishing", confidence=0.99, low_confidence=False,
            override_reason="virustotal_flagged",
        )

    if typosquat_target:
        return Verdict(
            verdict="phishing", confidence=0.9, low_confidence=False,
            override_reason="typosquat_lookalike",
        )

    # dns_resolves is False (not just falsy/None) -- None means the host
    # check itself didn't complete in time, which is a different, weaker
    # kind of "we don't know" already handled by whois_missing/rule 6
    # below, not a confirmed absence of any live site.
    if dns_resolves is False:
        return Verdict(
            verdict=prediction.verdict,
            confidence=prediction.confidence,
            low_confidence=True,
            override_reason="domain_unreachable",
        )

    if popularity_rank is not None and popularity_rank <= settings.popularity_override_rank:
        return Verdict(
            verdict="safe", confidence=0.95, low_confidence=False,
            override_reason="popular_domain",
        )

    no_track_record = whois_missing and popularity_rank is None
    if no_track_record and prediction.verdict == "phishing":
        return Verdict(
            verdict=prediction.verdict,
            confidence=prediction.confidence,
            low_confidence=True,
            override_reason="no_track_record",
        )

    return Verdict(
        verdict=prediction.verdict,
        confidence=prediction.confidence,
        low_confidence=prediction.low_confidence,
        override_reason=None,
    )
