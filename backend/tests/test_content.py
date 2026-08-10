from bs4 import BeautifulSoup

from app.features.content import _is_external, _meta_description, _page_title


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


def test_page_title_extracts_text():
    soup = BeautifulSoup("<html><head><title>  Example Site  </title></head></html>", "lxml")
    assert _page_title(soup) == "Example Site"


def test_page_title_none_when_missing():
    soup = BeautifulSoup("<html><head></head></html>", "lxml")
    assert _page_title(soup) is None


def test_meta_description_extracts_content():
    soup = BeautifulSoup(
        '<html><head><meta name="description" content="A great site."></head></html>', "lxml"
    )
    assert _meta_description(soup) == "A great site."


def test_meta_description_none_when_missing():
    soup = BeautifulSoup("<html><head></head></html>", "lxml")
    assert _meta_description(soup) is None
