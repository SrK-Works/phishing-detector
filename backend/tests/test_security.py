import pytest

from app.security import SSRFBlockedError, assert_host_is_safe, assert_url_is_safe


def test_blocks_loopback_literal():
    with pytest.raises(SSRFBlockedError):
        assert_host_is_safe("127.0.0.1")


def test_blocks_localhost_name():
    with pytest.raises(SSRFBlockedError):
        assert_host_is_safe("localhost")


def test_blocks_private_ranges():
    for ip in ["10.0.0.5", "172.16.0.5", "192.168.1.1"]:
        with pytest.raises(SSRFBlockedError):
            assert_host_is_safe(ip)


def test_blocks_link_local_metadata_ip():
    # cloud metadata endpoint (AWS/GCP/Azure all use this address)
    with pytest.raises(SSRFBlockedError):
        assert_host_is_safe("169.254.169.254")


def test_blocks_unspecified_and_multicast():
    with pytest.raises(SSRFBlockedError):
        assert_host_is_safe("0.0.0.0")
    with pytest.raises(SSRFBlockedError):
        assert_host_is_safe("224.0.0.1")


def test_allows_a_public_ip_literal():
    # 1.1.1.1 (Cloudflare DNS) is a stable, well-known public address
    assert_host_is_safe("1.1.1.1")


def test_rejects_non_http_scheme():
    with pytest.raises(SSRFBlockedError):
        assert_url_is_safe("file:///etc/passwd")
    with pytest.raises(SSRFBlockedError):
        assert_url_is_safe("ftp://example.com/")


def test_rejects_url_with_no_host():
    with pytest.raises(SSRFBlockedError):
        assert_url_is_safe("https:///path-only")
