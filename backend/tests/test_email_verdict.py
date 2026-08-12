from app.email_verdict import resolve_email_verdict


def _resolve(**overrides):
    defaults = dict(
        is_exact_brand=False,
        typosquat_matched=False,
        confirmed_threat=None,
        virustotal_malicious_count=None,
        dns_resolves=True,
        mx_present=True,
        spf_present=True,
        dmarc_present=True,
        domain_age_days=3650,
        popularity_rank=100,
        has_valid_https=True,
    )
    defaults.update(overrides)
    return resolve_email_verdict(**defaults)


def test_known_brand_domain_is_safe():
    resolved = _resolve(is_exact_brand=True)
    assert resolved.verdict == "safe"
    assert resolved.low_confidence is False
    assert resolved.override_reason == "known_brand_domain"


def test_confirmed_threat_beats_known_brand_domain():
    # A hijacked/compromised real brand domain must still be flagged, not
    # waved through just for being on the allowlist.
    resolved = _resolve(is_exact_brand=True, confirmed_threat=True)
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "confirmed_threat"


def test_virustotal_flagged_beats_known_brand_domain():
    resolved = _resolve(is_exact_brand=True, virustotal_malicious_count=5)
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "virustotal_flagged"


def test_virustotal_below_threshold_does_not_override():
    resolved = _resolve(virustotal_malicious_count=1)
    assert resolved.override_reason != "virustotal_flagged"


def test_confirmed_threat_beats_virustotal():
    resolved = _resolve(confirmed_threat=True, virustotal_malicious_count=10)
    assert resolved.override_reason == "confirmed_threat"


def test_typosquat_matched_is_phishing():
    resolved = _resolve(typosquat_matched=True)
    assert resolved.verdict == "phishing"
    assert resolved.override_reason == "typosquat_lookalike"


def test_confirmed_threat_beats_typosquat():
    resolved = _resolve(typosquat_matched=True, confirmed_threat=True)
    assert resolved.override_reason == "confirmed_threat"


def test_known_brand_domain_beats_typosquat():
    # is_exact_brand and typosquat_matched should never both be true in
    # practice (typosquat_target already excludes exact brand domains), but
    # the priority order should still hold if it somehow happened.
    resolved = _resolve(is_exact_brand=True, typosquat_matched=True)
    assert resolved.override_reason == "known_brand_domain"


def test_all_clean_signals_score_safe_with_confidence():
    resolved = _resolve()
    assert resolved.verdict == "safe"
    assert resolved.score == 0
    assert resolved.low_confidence is False
    assert resolved.override_reason is None


def test_missing_mx_alone_does_not_push_to_phishing():
    # A domain that resolves but has zero MX records could legitimately be
    # a send-only relay domain -- this signal alone (all else clean) must
    # never be decisive by itself.
    resolved = _resolve(mx_present=False)
    assert resolved.verdict == "safe"
    assert resolved.override_reason is None


def test_unknown_mx_spf_dmarc_are_not_scored_as_absent():
    # None means the DNS lookup itself failed (unknown), not a confirmed
    # absence -- only an explicit False should ever add points, the same
    # "None is never treated as clean/absent" convention as confirmed_threat
    # and virustotal elsewhere in this app.
    resolved = _resolve(mx_present=None, spf_present=None, dmarc_present=None)
    assert resolved.score == 0


def test_every_confirmed_absent_signal_stacked_scores_max_phishing():
    # Every soft signal explicitly confirmed absent -- this is the actual
    # "everything points to a spun-up-yesterday spoof domain" case the
    # scorer exists for. dns(30) + mx(25) + spf(15) + dmarc(15) + age(20) +
    # popularity(10) + https(5) = 120, capped at 100.
    resolved = _resolve(
        dns_resolves=False, mx_present=False, spf_present=False, dmarc_present=False,
        domain_age_days=None, popularity_rank=None, has_valid_https=False,
    )
    assert resolved.verdict == "phishing"
    assert resolved.override_reason is None
    assert resolved.score == 100


def test_score_near_threshold_is_low_confidence():
    # dns_resolves False (+30) + young domain (+20) == 50 -- past a
    # threshold of 40 but within the default 15-point margin, so this
    # should read as "leaning phishing but not certain", not confidently red.
    resolved = _resolve(dns_resolves=False, domain_age_days=5)
    assert resolved.score == 50
    assert resolved.verdict == "phishing"
    assert resolved.low_confidence is True


def test_score_far_past_threshold_is_not_low_confidence():
    resolved = _resolve(
        dns_resolves=False, mx_present=False, spf_present=False, dmarc_present=False,
        domain_age_days=None, popularity_rank=None, has_valid_https=False,
    )
    assert resolved.low_confidence is False
