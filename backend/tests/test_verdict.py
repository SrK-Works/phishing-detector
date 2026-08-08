from app.model.predict import Prediction
from app.verdict import resolve_verdict


def _prediction(verdict: str, confidence: float, low_confidence: bool) -> Prediction:
    return Prediction(
        verdict=verdict,
        confidence=confidence,
        legit_probability=confidence if verdict == "safe" else 1 - confidence,
        low_confidence=low_confidence,
        top_reasons=[],
    )


def test_confirmed_threat_overrides_everything():
    prediction = _prediction("safe", 0.95, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=1,
        confirmed_threat=True,
        typosquat_target=None,
        whois_missing=False,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "confirmed_threat"


def test_popular_domain_overrides_shaky_phishing_call():
    prediction = _prediction("phishing", 0.55, True)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=9790,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=False,
    )
    assert resolved.verdict == "safe"
    assert resolved.low_confidence is False
    assert resolved.override_reason == "popular_domain"


def test_unranked_domain_with_track_record_falls_back_to_model():
    prediction = _prediction("phishing", 0.6, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=False,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason is None


def test_popularity_rank_outside_threshold_does_not_override():
    prediction = _prediction("phishing", 0.6, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=900_000,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=False,
    )
    assert resolved.override_reason is None


def test_confirmed_threat_beats_popularity():
    prediction = _prediction("safe", 0.9, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=1,
        confirmed_threat=True,
        typosquat_target=None,
        whois_missing=False,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "confirmed_threat"


def test_typosquat_target_overrides_shaky_safe_call():
    # This is the paypa1.com case: the ML model alone said "safe" at 95.7%
    # because the small dataset has no aged-typosquat examples to weigh
    # against it. The typosquat rule must win regardless.
    prediction = _prediction("safe", 0.957, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=None,
        typosquat_target="paypal",
        whois_missing=False,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "typosquat_lookalike"


def test_typosquat_target_beats_popularity():
    prediction = _prediction("safe", 0.9, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=100,
        confirmed_threat=None,
        typosquat_target="paypal",
        whois_missing=False,
    )
    assert resolved.override_reason == "typosquat_lookalike"


def test_confirmed_threat_beats_typosquat():
    prediction = _prediction("safe", 0.9, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=True,
        typosquat_target="paypal",
        whois_missing=False,
    )
    assert resolved.override_reason == "confirmed_threat"


def test_no_track_record_softens_confident_phishing_to_uncertain():
    # This is the logiq-hub.lovable.app case: a brand-new site with no
    # WHOIS record and no Tranco ranking scored 91.7% phishing from the
    # model alone, purely because it looks like every other same-day
    # domain -- legit or not. The verdict/confidence should pass through
    # unchanged, but low_confidence must flip to True.
    prediction = _prediction("phishing", 0.917, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=True,
    )
    assert resolved.verdict == "phishing"
    assert resolved.confidence == 0.917
    assert resolved.low_confidence is True
    assert resolved.override_reason == "no_track_record"


def test_no_track_record_does_not_touch_a_safe_call():
    # One-directional: a new site the model already calls "safe" shouldn't
    # have doubt manufactured for it just for being new.
    prediction = _prediction("safe", 0.8, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=True,
    )
    assert resolved.verdict == "safe"
    assert resolved.low_confidence is False
    assert resolved.override_reason is None


def test_track_record_present_does_not_trigger_no_track_record_rule():
    # Only unranked AND whois-missing counts as "no track record" -- having
    # either one alone (e.g. ranked but WHOIS timed out) is not this case.
    prediction = _prediction("phishing", 0.9, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=500_000,
        confirmed_threat=None,
        typosquat_target=None,
        whois_missing=True,
    )
    assert resolved.override_reason is None


def test_typosquat_beats_no_track_record():
    # A brand-new typosquat domain is exactly the case rule 2 exists for --
    # it must not get softened into "uncertain" by rule 4.
    prediction = _prediction("safe", 0.8, False)
    resolved = resolve_verdict(
        prediction,
        popularity_rank=None,
        confirmed_threat=None,
        typosquat_target="paypal",
        whois_missing=True,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "typosquat_lookalike"
