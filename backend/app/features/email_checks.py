"""Email sending-domain trust signals: is this domain configured the way a
real organization's mail domain would be? Reuses the URL checker's own
WHOIS/DNS/TLS lookups (app.features.host) against a synthetic
`https://{domain}` URL rather than duplicating them -- "is this domain
trustworthy" is the same question whether it showed up in a URL or after
the @ in an email address.

DKIM is deliberately NOT checked here: a DKIM record lives at
`<selector>._domainkey.<domain>`, and the selector is chosen arbitrarily by
whichever mail provider sent the message (e.g. "google", "s1", "k1",
"mandrill") -- it's only knowable from a real email's own
`DKIM-Signature: s=` header, never from a bare domain or address. Since
this module only ever receives a domain/address, not a real message,
there's no honest way to check DKIM here -- faking it would be worse than
omitting it.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields

import dns.exception
import dns.resolver

from app.features import host


def extract_domain(raw: str) -> str:
    """Accepts a bare domain ("example.com") or a full address
    ("user@example.com"); returns the lowercased, whitespace-trimmed
    domain. Only splits on the *last* "@" (technically valid in the local
    part) and returns "" for input with no domain at all.
    """
    value = raw.strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.strip(".")


def _query_txt(name: str, timeout: float) -> list[str] | None:
    """TXT record values for `name`. [] if the name exists but has no TXT
    records (or doesn't exist at all) -- a real, checkable "absent". None
    if the lookup itself failed (timeout, no nameservers reachable, ...) --
    callers must treat that as "unknown", never as "absent", same
    convention as app.features.reputation's None handling.
    """
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    # Each TXT rdata can be split across multiple <=255-byte strings; join
    # them back into one value per record before matching prefixes below.
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]


def has_mx_records(domain: str, timeout: float) -> bool | None:
    try:
        dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except dns.exception.DNSException:
        return None


def has_spf_record(domain: str, timeout: float) -> bool | None:
    records = _query_txt(domain, timeout)
    if records is None:
        return None
    return any(r.startswith("v=spf1") for r in records)


def has_dmarc_record(domain: str, timeout: float) -> bool | None:
    records = _query_txt(f"_dmarc.{domain}", timeout)
    if records is None:
        return None
    return any(r.startswith("v=DMARC1") for r in records)


@dataclass(frozen=True)
class EmailDomainFeatures:
    dns_resolves: bool
    mx_present: bool | None
    spf_present: bool | None
    dmarc_present: bool | None
    domain_age_days: int | None
    has_valid_https: bool

    def as_dict(self) -> dict[str, float | int | bool | None]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def extract_email_domain_features(domain: str, timeout: float) -> EmailDomainFeatures:
    url = f"https://{domain}"
    resolves = host.dns_resolves(url)
    if not resolves:
        return EmailDomainFeatures(
            dns_resolves=False,
            mx_present=None,
            spf_present=None,
            dmarc_present=None,
            domain_age_days=None,
            has_valid_https=False,
        )

    # All independent network calls; run concurrently so the worst case
    # stays ~1x `timeout` rather than growing with each additional check,
    # same reasoning as host.extract_host_features's own pool.
    with ThreadPoolExecutor(max_workers=5) as pool:
        mx_future = pool.submit(has_mx_records, domain, timeout)
        spf_future = pool.submit(has_spf_record, domain, timeout)
        dmarc_future = pool.submit(has_dmarc_record, domain, timeout)
        whois_future = pool.submit(host.lookup_whois, url, timeout)
        cert_future = pool.submit(host.tls_cert_age_days, url, timeout)

        mx_present = mx_future.result()
        spf_present = spf_future.result()
        dmarc_present = dmarc_future.result()
        whois_info = whois_future.result()
        cert_age = cert_future.result()

    return EmailDomainFeatures(
        dns_resolves=True,
        mx_present=mx_present,
        spf_present=spf_present,
        dmarc_present=dmarc_present,
        domain_age_days=host.domain_age_days(whois_info),
        has_valid_https=cert_age is not None,
    )
