from app.features.content import _is_external


def test_same_domain_is_not_external():
    assert _is_external("google.com", "google.com") is False


def test_unrelated_domain_is_external():
    assert _is_external("google.com", "evil-attacker.com") is True


def test_known_infra_domain_is_not_external():
    # This is the accounts.google.com / en.wikipedia.org case: a page
    # loading assets from a sibling domain it also owns (or a generic
    # public CDN) shouldn't score identically to one pulling scripts from
    # a genuinely unrelated attacker domain.
    assert _is_external("google.com", "gstatic.com") is False
    assert _is_external("wikipedia.org", "wikimedia.org") is False
    assert _is_external("some-random-site.com", "cdnjs.cloudflare.com") is False


def test_empty_domain_is_not_external():
    assert _is_external("google.com", "") is False
