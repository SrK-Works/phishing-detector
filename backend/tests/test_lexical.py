from app.features.lexical import (
    brand_display_name,
    brand_typosquat_distance,
    digit_ratio_in_domain,
    domain_entropy,
    extract_lexical_features,
    has_at_symbol,
    has_double_slash_redirect,
    has_ip_address,
    has_suspicious_tld,
    is_checkable_web_url,
    is_exact_brand_domain,
    known_brand_slug,
    looks_like_bare_email,
    looks_like_url,
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
    match = typosquat_target("https://paypa1.com/login")
    assert match.brand == "paypal"
    assert match.real_domain == "paypal.com"
    assert match.diff_description == 'the letter "1" was swapped for "l"'


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
    match = typosquat_target("https://paypal-secure-login.com/")
    assert match.brand == "paypal"
    assert match.diff_description is None  # no single "letter swap" for this pattern
    assert typosquat_target("https://amazon-account-verify.net/").brand == "amazon"


def test_typosquat_target_does_not_flag_unrelated_hyphenated_domain():
    assert typosquat_target("https://my-startup-name.com/") is None


def test_typosquat_target_ignores_short_name_even_at_edit_distance_one():
    # "ets" (ets.org, the real Educational Testing Service / GRE site) is
    # edit-distance 1 from "etsy" -- exactly at the old ratio cutoff
    # (1/4 == 0.25) -- so it used to be flagged as a lookalike despite being
    # a genuine, well-established, unrelated domain.
    assert typosquat_target("https://ets.org/") is None


def test_typosquat_target_flags_indian_bank_lookalike():
    # "hdtc" instead of "hdfc" -- exactly the real-world case that prompted
    # this: a single misplaced letter in a bank name is the classic
    # phishing pattern a user is likely to overlook at a glance.
    match = typosquat_target("https://hdtc.com/")
    assert match.brand == "hdfc"
    assert match.real_domain == "hdfcbank.com"
    assert match.diff_description == 'the letter "t" was swapped for "f"'


def test_typosquat_target_does_not_flag_real_brand_domain_with_different_slug():
    # "hdfc" (the typosquat slug) and "hdfcbank" (the real domain's own
    # name) are deliberately different strings -- the real site itself
    # must never be flagged as a lookalike of its own brand slug.
    assert typosquat_target("https://hdfcbank.com/") is None
    assert is_exact_brand_domain("https://hdfcbank.com/") is True


def test_bank_in_subdomains_are_treated_as_distinct_registrable_domains():
    # The bug this guards against: yonosbi.bank.in doesn't resolve to
    # anything real, but bank.in itself is a popular, Tranco-ranked domain
    # (real banks use it) -- without extra_suffixes, both are misparsed as
    # the single shared entity "bank.in", handing a fake subdomain the
    # real one's popularity.
    assert registered_domain("https://yonosbi.bank.in") == "yonosbi.bank.in"
    assert registered_domain("https://au.bank.in") == "au.bank.in"
    assert registered_domain("https://sbi.fin.in") == "sbi.fin.in"


def test_extract_lexical_features_returns_all_fields():
    feats = extract_lexical_features("https://login.paypa1-secure.tk/verify@evil.com")
    d = feats.as_dict()
    assert d["has_at_symbol"] is True
    assert d["has_suspicious_tld"] is True
    assert isinstance(d["url_length"], int)


def test_typosquat_target_flags_recruitment_scam_lookalike():
    # The exact gap that motivated adding IT/consulting employers to the
    # brand list: a "z" -> "g" swap impersonating Cognizant in a fake
    # recruitment email domain.
    match = typosquat_target("https://cognigant.com")
    assert match is not None
    assert match.brand == "cognizant"
    assert match.real_domain == "cognizant.com"
    assert 'swapped for "z"' in match.diff_description


def test_known_brand_slug_matches_real_domain():
    assert known_brand_slug("https://cognizant.com") == "cognizant"
    assert known_brand_slug("https://hdfcbank.com") == "hdfc"
    assert known_brand_slug("https://some-unrelated-site.com") is None


def test_brand_display_name_falls_back_to_title_case():
    assert brand_display_name("cognizant") == "Cognizant"
    assert brand_display_name("hdfc") == "HDFC Bank"
    assert brand_display_name("some-unlisted-slug") == "Some Unlisted Slug"


def test_looks_like_bare_email_flags_plain_addresses():
    # The exact live case: "noreply@email.openai.com" pasted into the URL
    # checker silently became "https://noreply@email.openai.com" (userinfo
    # "noreply", host "email.openai.com") -- a real but confusing result.
    assert looks_like_bare_email("noreply@email.openai.com") is True
    assert looks_like_bare_email("support@openai.com") is True
    assert looks_like_bare_email("  support@openai.com  ") is True


def test_looks_like_bare_email_does_not_flag_urls_with_userinfo():
    # A deliberately-constructed URL with credentials, or a path segment
    # that happens to contain "@", must never be misclassified -- both
    # contain "://" or "/", which a bare email address never does.
    assert looks_like_bare_email("https://user@host.com") is False
    assert looks_like_bare_email("example.com/page@2x.jpg") is False
    assert looks_like_bare_email("example.com") is False


def test_looks_like_url_flags_urls():
    assert looks_like_url("https://example.com") is True
    assert looks_like_url("example.com/login") is True
    assert looks_like_url("http://example.com/login?token=abc") is True


def test_looks_like_url_does_not_flag_bare_domain_or_email():
    assert looks_like_url("example.com") is False
    assert looks_like_url("support@example.com") is False


def test_is_checkable_web_url_accepts_normal_urls():
    assert is_checkable_web_url("https://google.com") is True
    assert is_checkable_web_url("http://example.com/path?q=1") is True
    assert is_checkable_web_url("https://user:pass@example.com") is True


def test_is_checkable_web_url_accepts_ip_literals():
    # IP-literal URLs are still checkable -- has_ip_address is itself a
    # model feature (a real phishing signal), not something to reject.
    assert is_checkable_web_url("http://8.8.8.8") is True
    assert is_checkable_web_url("http://192.168.1.1") is True


def test_is_checkable_web_url_rejects_non_http_schemes():
    # Live-caught: "ftp://example.com" previously sailed through and
    # returned a confident-looking "safe" verdict for a protocol this app
    # has no way to meaningfully assess.
    assert is_checkable_web_url("ftp://example.com/file.txt") is False
    assert is_checkable_web_url("file:///etc/passwd") is False


def test_is_checkable_web_url_rejects_pseudo_url_after_prefixing():
    # Live-caught: "javascript:alert(1)" has no "://", so the caller's own
    # "prepend https://" step turns it into "https://javascript:alert(1)"
    # -- which parses without ever being a real address, and previously
    # returned a fabricated "83% confident safe" verdict instead of being
    # rejected outright.
    assert is_checkable_web_url("https://javascript:alert(1)") is False
    assert is_checkable_web_url("https://data:text/html,<script>alert(1)</script>") is False


def test_is_checkable_web_url_rejects_hostless_or_suffixless_hosts():
    assert is_checkable_web_url("http://localhost") is False
    assert is_checkable_web_url("http://intranet") is False
