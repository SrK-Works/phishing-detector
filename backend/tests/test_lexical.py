from app.features.lexical import (
    brand_typosquat_distance,
    digit_ratio_in_domain,
    domain_entropy,
    extract_lexical_features,
    has_at_symbol,
    has_double_slash_redirect,
    has_ip_address,
    has_suspicious_tld,
    is_exact_brand_domain,
    registered_domain,
    subdomain_count,
    typosquat_target,
    url_length,
    uses_https,
    uses_url_shortener,
)


def test_registered_domain():
    assert registered_domain("https://accounts.login.paypal.com/x") == "paypal.com"
    assert registered_domain("http://example.co.uk/path") == "example.co.uk"


def test_has_ip_address():
    assert has_ip_address("http://192.168.1.1/login") is True
    assert has_ip_address("http://0x1.0x2.0x3.0x4/login") is True
    assert has_ip_address("https://paypal.com/login") is False


def test_url_length_matches_len():
    url = "https://example.com/" + "a" * 100
    assert url_length(url) == len(url)


def test_uses_url_shortener():
    assert uses_url_shortener("https://bit.ly/3xyz") is True
    assert uses_url_shortener("https://tinyurl.com/abc") is True
    assert uses_url_shortener("https://example.com/abc") is False


def test_has_at_symbol():
    assert has_at_symbol("https://example.com@evil.com/") is True
    assert has_at_symbol("https://example.com/") is False


def test_has_double_slash_redirect():
    assert has_double_slash_redirect("https://example.com//https://evil.com") is True
    assert has_double_slash_redirect("https://example.com/path/to/page") is False


def test_subdomain_count():
    assert subdomain_count("https://paypal.com/") == 0
    assert subdomain_count("https://login.paypal.com/") == 1
    assert subdomain_count("https://a.b.c.paypal.com/") == 3


def test_uses_https():
    assert uses_https("https://example.com/") is True
    assert uses_https("http://example.com/") is False


def test_digit_ratio_in_domain():
    assert digit_ratio_in_domain("https://paypal.com/") == 0.0
    assert digit_ratio_in_domain("https://paypal123.com/") > 0.0


def test_domain_entropy_higher_for_random_strings():
    assert domain_entropy("https://aaaaaaaa.com/") < domain_entropy("https://x7q2z9wm.com/")


def test_has_suspicious_tld():
    assert has_suspicious_tld("https://free-gift.tk/") is True
    assert has_suspicious_tld("https://paypal.com/") is False


def test_brand_typosquat_distance_flags_near_misses():
    # 'paypa1' is one edit away from 'paypal' but is not the real domain
    close = brand_typosquat_distance("https://paypa1.com/login")
    exact = brand_typosquat_distance("https://paypal.com/login")
    unrelated = brand_typosquat_distance("https://some-random-blog-site.com/")
    assert exact == 0
    assert close == 1
    assert unrelated > close


def test_is_exact_brand_domain():
    assert is_exact_brand_domain("https://paypal.com/login") is True
    assert is_exact_brand_domain("https://paypa1.com/login") is False


def test_typosquat_target_flags_close_lookalike():
    assert typosquat_target("https://paypa1.com/login") == "paypal"


def test_typosquat_target_none_for_real_brand():
    assert typosquat_target("https://paypal.com/login") is None


def test_typosquat_target_none_for_unrelated_domain():
    assert typosquat_target("https://some-random-blog-site.com/") is None


def test_typosquat_target_ignores_short_domain_false_positive():
    # "app.com" is a real, unrelated domain; it shouldn't be flagged as a
    # lookalike of "apple" just because it's a short edit distance away.
    assert typosquat_target("https://app.com/") is None


def test_typosquat_target_flags_brand_name_stuffing():
    # A classic pattern the old has_hyphen_in_domain feature was meant to
    # catch, imprecisely -- this replaces it with a brand-specific check.
    assert typosquat_target("https://paypal-secure-login.com/") == "paypal"
    assert typosquat_target("https://amazon-account-verify.net/") == "amazon"


def test_typosquat_target_does_not_flag_unrelated_hyphenated_domain():
    assert typosquat_target("https://my-startup-name.com/") is None


def test_extract_lexical_features_returns_all_fields():
    feats = extract_lexical_features("https://login.paypa1-secure.tk/verify@evil.com")
    d = feats.as_dict()
    assert d["has_at_symbol"] is True
    assert d["has_suspicious_tld"] is True
    assert isinstance(d["url_length"], int)
