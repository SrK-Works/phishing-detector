"""Pure, offline URL features: no network calls, safe to run on any input.

Every function takes a URL string and returns a float/bool/int. They are
deliberately side-effect free so they can be unit tested without mocking
anything, and so the API can return a preliminary verdict instantly before
the slower host/content checks (see app.features.host / app.features.content)
resolve.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

import tldextract

# Bundled public-suffix-list snapshot only; never fetch over the network.
# include_psl_private_domains=True matters here: without it, tldextract only
# recognizes official ICANN TLDs, so multi-tenant hosting platforms in the
# PSL's "private" section (github.io, blogspot.com, netlify.app, s3
# buckets, ...) get misparsed as if the platform name itself were the
# registrable domain (e.g. "evil-user.github.io" -> domain="github"). That
# both breaks the typosquat/brand check (falsely "matching" the platform's
# own name) and misses the real signal: phishing kits are commonly hosted
# on exactly these free platforms, where the subdomain is the attacker's.
#
# extra_suffixes covers the same failure mode for namespaces the bundled
# PSL snapshot doesn't track at all (not even in its "private" section):
# India's ".bank.in" and ".fin.in" were launched in 2025 by NIXI/RBI
# specifically so different banks/NBFCs each register directly under a
# shared, regulator-verified suffix (e.g. "au.bank.in", "yes.bank.in") --
# the same multi-tenant shape as github.io, just not yet PSL-tracked.
# Without this, EVERY subdomain of bank.in -- including one that doesn't
# even resolve -- was misparsed as the single shared entity "bank.in",
# which is itself a real, popular, Tranco-ranked domain (real banks use
# it) -- so a completely fake "yonosbi.bank.in" inherited that popularity
# and was confidently called "safe". Caught via live testing, not a
# hypothetical: see docs/DATASET.md.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    extra_suffixes=["bank.in", "fin.in"],
)

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV4_HEX_RE = re.compile(r"^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")

_SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co",
    "tinyurl.com", "tr.im", "is.gd", "cli.gs", "tiny.cc", "url4.eu",
    "su.pr", "snipurl.com", "short.to", "buff.ly", "rebrand.ly", "cutt.ly",
    "bit.do", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "po.st", "v.gd",
}

_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "ga", "cf", "work",
    "click", "link", "loan", "download", "review", "country", "kim",
}

# High-value phishing targets: brands attackers commonly impersonate
# (banking, payments, shipping/delivery, email/social, shopping, crypto,
# e-signature, government services). Deliberately excludes 1-2 char names
# (e.g. "x") -- those sit within edit-distance-2 of huge swaths of
# unrelated real domains. `typosquat_target` below additionally guards
# short brand names with a distance-to-length ratio, a minimum name
# length, and a length-window filter so it doesn't fire on every short
# real domain (see docs/DATASET.md bug #5 -- "ets" vs "etsy" -- for why
# those guards exist).
#
# Maps the short, recognizable slug a typosquatter would actually target
# (what people type/search) to that brand's *real* full domain, used for
# UI display ("the real domain is Y") -- these are deliberately different
# things: e.g. slug "hdfc" (what someone would misspell) vs real domain
# "hdfcbank.com" (what they should actually go to). Getting the real
# domain wrong here would be worse than not knowing it at all, so every
# entry below is either an extremely well-known global brand or was
# verified via web search while building this list (2026-08) rather than
# guessed -- this list is deliberately not exhaustive; growing it further
# should keep that same verify-before-adding discipline rather than
# batch-adding unverified names for the sake of raw count.
_BRAND_DOMAINS: dict[str, str] = {
    # Global tech / social / email
    "google": "google.com", "facebook": "facebook.com", "amazon": "amazon.com",
    "apple": "apple.com", "microsoft": "microsoft.com", "netflix": "netflix.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "chatgpt": "chatgpt.com", "openai": "openai.com",
    "dropbox": "dropbox.com", "github": "github.com", "gmail": "gmail.com",
    "outlook": "outlook.com", "icloud": "icloud.com", "yahoo": "yahoo.com",
    "spotify": "spotify.com", "tiktok": "tiktok.com", "snapchat": "snapchat.com",
    "pinterest": "pinterest.com", "reddit": "reddit.com", "adobe": "adobe.com",
    "docusign": "docusign.com",
    # Global banking / payments / crypto
    "paypal": "paypal.com", "bankofamerica": "bankofamerica.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "citibank": "citibank.com", "hsbc": "hsbc.com",
    "capitalone": "capitalone.com", "usbank": "usbank.com", "venmo": "venmo.com",
    "stripe": "stripe.com", "cashapp": "cashapp.com", "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",  # not .com -- caught and fixed while building this list
    # Global shopping / shipping
    "ebay": "ebay.com", "usps": "usps.com", "fedex": "fedex.com", "ups": "ups.com",
    "dhl": "dhl.com", "walmart": "walmart.com", "target": "target.com",
    "etsy": "etsy.com", "aliexpress": "aliexpress.com",
    # Global telecom / gaming
    "verizon": "verizon.com", "tmobile": "tmobile.com", "steamcommunity": "steamcommunity.com",

    # Indian banks -- real domains verified via web search (2026-08), not
    # guessed. Several (bankofbaroda, aubank, yesbank) have confirmed live
    # ".bank.in" domains, the new RBI/NIXI-mandated anti-phishing namespace
    # this same fix now correctly recognizes as a suffix (see above).
    "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
    "kotak": "kotak.com", "sbi": "sbi.co.in", "pnb": "pnbindia.in",
    "bankofbaroda": "bankofbaroda.in", "unionbank": "unionbankofindia.co.in",
    "bankofindia": "bankofindia.co.in", "federalbank": "federalbank.co.in",
    "aubank": "au.bank.in", "yesbank": "yesbank.in", "idbibank": "idbibank.in",
    "indusind": "indusind.com", "idfcfirst": "idfcfirstbank.com",
    "rblbank": "rblbank.com", "bandhanbank": "bandhanbank.com",
    "canarabank": "canarabank.com",
    # Indian government / public services (very high-value phishing
    # targets: tax refunds, identity documents, rail bookings)
    "incometax": "incometax.gov.in", "uidai": "uidai.gov.in",
    "epfindia": "epfindia.gov.in", "gst": "gst.gov.in",
    "digilocker": "digilocker.gov.in", "irctc": "irctc.co.in",
    "passportindia": "passportindia.gov.in",
    # Indian payments / fintech
    "paytm": "paytm.com", "phonepe": "phonepe.com", "mobikwik": "mobikwik.com",
    "freecharge": "freecharge.in", "bhimupi": "bhimupi.org.in", "npci": "npci.org.in",
    # Indian e-commerce
    "flipkart": "flipkart.com", "myntra": "myntra.com", "snapdeal": "snapdeal.com",
    "meesho": "meesho.com", "bigbasket": "bigbasket.com", "nykaa": "nykaa.com",
    # Indian telecom
    "jio": "jio.com", "airtel": "airtel.in", "myvi": "myvi.in",

    # IT services / consulting / BPO -- the companies most often impersonated
    # in "you've been shortlisted, click here to submit documents" recruitment
    # phishing, which doesn't target banks/payments at all. Verified via web
    # search (2026-08), same discipline as the rest of this list.
    "tcs": "tcs.com", "infosys": "infosys.com", "wipro": "wipro.com",
    "hcltech": "hcltech.com", "techmahindra": "techmahindra.com",
    "capgemini": "capgemini.com", "genpact": "genpact.com",
    "concentrix": "concentrix.com", "persistent": "persistent.com",
    "cyient": "cyient.com", "wns": "wns.com", "firstsource": "firstsource.com",
    "teleperformance": "teleperformance.com", "mphasis": "mphasis.com",
    "accenture": "accenture.com", "deloitte": "deloitte.com", "ey": "ey.com",
    "kpmg": "kpmg.com", "pwc": "pwc.com", "oracle": "oracle.com", "sap": "sap.com",
    "ibm": "ibm.com",
    "dell": "dell.com", "cisco": "cisco.com", "intel": "intel.com",
    "qualcomm": "qualcomm.com", "salesforce": "salesforce.com",
    "servicenow": "servicenow.com", "vmware": "vmware.com",
    # Cognizant was the exact gap that motivated this section:
    # talentacquisition@cognigant.com (a "z"->"g" swap) scored "legitimate"
    # because "cognizant" simply wasn't in this list yet to compare against.
    "cognizant": "cognizant.com",
    # LTIMindtree rebranded to "LTM" in 2026 (regulatory approval, new
    # Certificate of Incorporation) -- both the old and new name are live
    # phishing targets, so both slugs point at the current real domain.
    "ltimindtree": "ltm.com", "ltm": "ltm.com",
    # Job portals -- recruitment scams commonly reference or impersonate
    # these directly, not just the employer.
    "naukri": "naukri.com", "indeed": "indeed.com",

    # Airlines -- "your booking/refund needs confirmation" is one of the
    # most universal phishing lures there is, independent of who the
    # target banks with or where they work. Verified via web search
    # (2026-08).
    "indigo": "goindigo.in", "airindia": "airindia.com", "spicejet": "spicejet.com",
    "emirates": "emirates.com", "qatarairways": "qatarairways.com",
    "delta": "delta.com", "united": "united.com", "americanairlines": "aa.com",
    "lufthansa": "lufthansa.com", "britishairways": "britishairways.com",
    # Couriers -- "your parcel couldn't be delivered, pay this fee to
    # release it" is the courier-flavored version of the same lure, and one
    # of the most common phishing/smishing patterns in India specifically.
    "bluedart": "bluedart.com", "delhivery": "delhivery.com", "dtdc": "dtdc.in",
    "indiapost": "indiapost.gov.in", "ecomexpress": "ecomexpress.in",
    # Indian insurance -- policy renewal/lapse scams are a major, distinct
    # phishing category in India. Two rebrand gotchas caught while verifying
    # (2026-08): Max Life Insurance is now "Axis Max Life Insurance" at
    # axismaxlife.com (rebranded Dec 2024, old maxlifeinsurance.com is
    # stale), and Bajaj Allianz Life is now "Bajaj Life Insurance" at
    # bajajlifeinsurance.com, not bajajallianz.com as the old name would
    # suggest -- exactly the kind of wrong-guess this list's verify-first
    # discipline exists to catch.
    "lic": "licindia.in", "hdfclife": "hdfclife.com",
    "iciciprulife": "iciciprulife.com", "maxlife": "axismaxlife.com",
    "bajajallianz": "bajajlifeinsurance.com",
    # More Indian product/tech companies -- account-security and
    # recruitment phishing both target these directly (food delivery,
    # ride-hailing, fintech, and ed-tech accounts all carry saved payment
    # methods, and all of these are also major employers).
    "zoho": "zoho.com", "freshworks": "freshworks.com", "razorpay": "razorpay.com",
    "swiggy": "swiggy.com", "zomato": "zomato.com", "ola": "olacabs.com",
    "cred": "cred.club", "byjus": "byjus.com", "groww": "groww.in",
    "zerodha": "zerodha.com", "upstox": "upstox.com", "policybazaar": "policybazaar.com",
    # More global banks
    "standardchartered": "sc.com", "deutschebank": "db.com", "dbs": "dbs.com",
    # Streaming
    "hotstar": "hotstar.com",
    # Freelance/gig platforms -- adjacent to the recruitment-scam theme
    # this section started with (fake job offers routed through these too).
    "upwork": "upwork.com", "fiverr": "fiverr.com",

    # Round 2 general expansion (163 -> ~250), prioritizing brands with the
    # highest real-world phishing/smishing volume: account-security lures
    # (cloud/SaaS, crypto, banking), delivery/booking lures (travel), and
    # subscription-renewal lures (streaming) are the biggest categories
    # globally, on top of the recruitment/India-specific ones already
    # covered above. Verified via web search (2026-08); a few caught
    # mid-verification below are flagged inline the same way earlier
    # rebrand gotchas were.

    # Global tech / cloud/SaaS accounts
    "zoom": "zoom.com", "slack": "slack.com", "atlassian": "atlassian.com",
    "godaddy": "godaddy.com", "namecheap": "namecheap.com", "cloudflare": "cloudflare.com",
    "discord": "discord.com", "telegram": "telegram.org", "youtube": "youtube.com",
    "twitch": "twitch.tv", "signal": "signal.org", "tinder": "tinder.com",
    "bumble": "bumble.com", "norton": "norton.com", "mcafee": "mcafee.com",
    "grammarly": "grammarly.com", "canva": "canva.com", "notion": "notion.so",
    "figma": "figma.com",

    # More global banks
    "santander": "santander.com", "bbva": "bbva.com", "revolut": "revolut.com",
    "wise": "wise.com", "chime": "chime.com", "tdbank": "tdbank.com",
    "pnc": "pnc.com", "truist": "truist.com",

    # Crypto exchanges -- among the highest-value phishing targets there
    # is, since a successful account-takeover here means an irreversible
    # loss. wazirx.com is a live, current phishing target: a WazirX-hack
    # compensation-payout phishing wave was active as of this verification.
    "kraken": "kraken.com", "cryptocom": "crypto.com", "kucoin": "kucoin.com",
    "gemini": "gemini.com", "bitfinex": "bitfinex.com", "wazirx": "wazirx.com",
    "coindcx": "coindcx.com", "robinhood": "robinhood.com",

    # Global retail -- "your order/delivery" and fake-storefront lures
    "costco": "costco.com", "ikea": "ikea.com", "bestbuy": "bestbuy.com",
    "homedepot": "homedepot.com", "lowes": "lowes.com", "nike": "nike.com",
    "adidas": "adidas.com", "zara": "zara.com", "sephora": "sephora.com",
    "wayfair": "wayfair.com",

    # Payment/fintech
    "klarna": "klarna.com", "afterpay": "afterpay.com",
    "westernunion": "westernunion.com", "moneygram": "moneygram.com",
    "zelle": "zelle.com", "square": "squareup.com",

    # Streaming/subscription -- "your subscription payment failed, update
    # your card" is one of the most common renewal-scam lures. HBO Max
    # rebranded to plain "Max" in 2023, then rebranded BACK to "HBO Max" in
    # July 2025 -- caught mid-verification, confirmed hbomax.com is the
    # current live domain, not max.com.
    "disneyplus": "disneyplus.com", "hulu": "hulu.com", "hbomax": "hbomax.com",
    "peacock": "peacocktv.com", "paramountplus": "paramountplus.com",

    # Gaming -- account-takeover phishing (stored payment methods, item/
    # currency trading) is extremely common in this category
    "playstation": "playstation.com", "xbox": "xbox.com", "nintendo": "nintendo.com",
    "epicgames": "epicgames.com", "roblox": "roblox.com",

    # Travel/hospitality -- fake booking confirmation/cancellation is the
    # same lure pattern as the airlines section above, one layer up the
    # booking chain
    "booking": "booking.com", "airbnb": "airbnb.com", "expedia": "expedia.com",
    "tripadvisor": "tripadvisor.com", "marriott": "marriott.com", "hilton": "hilton.com",
    "makemytrip": "makemytrip.com", "goibibo": "goibibo.com", "ryanair": "ryanair.com",
    "easyjet": "easyjet.com",

    # More job/recruitment platforms
    "glassdoor": "glassdoor.com", "monster": "monster.com",
    "ziprecruiter": "ziprecruiter.com", "shine": "shine.com",

    # Indian NBFC/lending -- fake loan-approval/EMI scams are a major,
    # distinct phishing category in India
    "bajajfinserv": "bajajfinserv.in", "muthootfinance": "muthootfinance.com",
    # PAN card services -- a very high-value target (tax fraud, identity
    # theft). NSDL e-Governance rebranded to "Protean eGov Technologies" --
    # both old and new names are live phishing targets, same reasoning as
    # the LTIMindtree/LTM entry above.
    "nsdl": "proteantech.in", "protean": "proteantech.in",

    # More Indian consumer apps
    "urbancompany": "urbancompany.com", "lenskart": "lenskart.com",
    "pharmeasy": "pharmeasy.in",

    # More global telecom
    "vodafone": "vodafone.com", "att": "att.com",
}

# Since a brand's slug (the typosquat target, e.g. "hdfc") and its real
# domain's own name (e.g. "hdfcbank") now deliberately differ, the real
# domain itself needs a separate exemption from typosquat matching -- a
# visitor to the actual hdfcbank.com must never be told it looks like a
# lookalike of something else. Computed once at import time, not per
# request. Keeps the slug alongside (rather than just a bare set) so a
# visitor to the real domain can also be told *whose* real domain it is
# (see known_brand_slug/brand_display_name below) -- a plain yes/no exact-
# match boolean isn't enough to show "this is the real domain for X".
_DOMAIN_NAME_TO_SLUG: dict[str, str] = {
    _extract(f"https://{d}").domain.lower(): slug for slug, d in _BRAND_DOMAINS.items()
}
_REAL_DOMAIN_NAMES = set(_DOMAIN_NAME_TO_SLUG)

# Only entries where naively title-casing the slug wouldn't read like the
# company's actual name (initialisms, stylized capitalization, names that
# differ from the slug entirely) -- everything else falls back to
# `slug.title()`, which is already correct for the large majority of
# single-word brand names in this list (e.g. "cognizant" -> "Cognizant").
_BRAND_DISPLAY_NAMES: dict[str, str] = {
    "hdfc": "HDFC Bank", "icici": "ICICI Bank", "axis": "Axis Bank",
    "sbi": "State Bank of India (SBI)", "pnb": "Punjab National Bank (PNB)",
    "hsbc": "HSBC", "usbank": "U.S. Bank", "paypal": "PayPal",
    "aubank": "AU Small Finance Bank", "idbibank": "IDBI Bank",
    "indusind": "IndusInd Bank", "idfcfirst": "IDFC FIRST Bank",
    "rblbank": "RBL Bank", "uidai": "UIDAI (Aadhaar)", "gst": "GST Portal (India)",
    "epfindia": "EPFO (India)", "irctc": "IRCTC", "npci": "NPCI",
    "bhimupi": "BHIM UPI", "hcltech": "HCLTech", "techmahindra": "Tech Mahindra",
    "wns": "WNS Global Services", "ey": "EY (Ernst & Young)", "kpmg": "KPMG",
    "pwc": "PwC", "sap": "SAP", "ibm": "IBM", "tcs": "TCS (Tata Consultancy Services)",
    "ltimindtree": "LTM (formerly LTIMindtree)", "ltm": "LTM (formerly LTIMindtree)",
    "vmware": "VMware", "chatgpt": "ChatGPT (OpenAI)", "openai": "OpenAI",
    "tmobile": "T-Mobile", "myvi": "My Vi (Vodafone Idea)",
    "indigo": "IndiGo", "airindia": "Air India", "spicejet": "SpiceJet",
    "americanairlines": "American Airlines", "britishairways": "British Airways",
    "qatarairways": "Qatar Airways", "united": "United Airlines",
    "dtdc": "DTDC", "indiapost": "India Post", "ecomexpress": "Ecom Express",
    "bluedart": "Blue Dart",
    "lic": "LIC (Life Insurance Corporation of India)",
    "hdfclife": "HDFC Life", "iciciprulife": "ICICI Prudential Life Insurance",
    "maxlife": "Axis Max Life Insurance (formerly Max Life)",
    "bajajallianz": "Bajaj Life Insurance (formerly Bajaj Allianz Life)",
    "ola": "Ola Cabs", "cred": "CRED", "byjus": "BYJU'S",
    "policybazaar": "PolicyBazaar",
    "standardchartered": "Standard Chartered", "deutschebank": "Deutsche Bank",
    "dbs": "DBS Bank", "hotstar": "Disney+ Hotstar",
    "youtube": "YouTube", "godaddy": "GoDaddy",
    "bbva": "BBVA", "tdbank": "TD Bank", "pnc": "PNC Bank",
    "cryptocom": "Crypto.com", "kucoin": "KuCoin", "wazirx": "WazirX",
    "coindcx": "CoinDCX",
    "bestbuy": "Best Buy", "homedepot": "The Home Depot", "lowes": "Lowe's",
    "hbomax": "HBO Max", "disneyplus": "Disney+", "paramountplus": "Paramount+",
    "ziprecruiter": "ZipRecruiter", "easyjet": "easyJet",
    "bajajfinserv": "Bajaj Finserv", "muthootfinance": "Muthoot Finance",
    "nsdl": "NSDL (now Protean eGov)", "protean": "Protean eGov Technologies",
    "urbancompany": "Urban Company", "pharmeasy": "PharmEasy", "att": "AT&T",
}


def brand_display_name(slug: str) -> str:
    return _BRAND_DISPLAY_NAMES.get(slug, slug.replace("-", " ").title())


def known_brand_slug(url: str) -> str | None:
    """Which brand slug this URL's registrable domain exactly matches, or
    None if it doesn't match any known brand's real domain at all.
    Distinct from is_exact_brand_domain (bool only) -- needed to surface a
    human-readable company name ("this is the real domain for X") rather
    than a bare yes/no.
    """
    parts = _extract(url)
    name = parts.domain.lower()
    if name in _BRAND_DOMAINS:
        return name
    return _DOMAIN_NAME_TO_SLUG.get(name)

# Below this length, edit-distance matching against a brand name stops being
# a real signal: a short domain has a rapidly rising chance of landing
# within distance 1 of *some* brand purely by coincidence as the brand list
# above grows (e.g. "ets" vs "etsy" -- a real, well-established site, not a
# lookalike). This is a floor on the candidate name itself, independent of
# the distance/length ratio in typosquat_target() below, because the ratio
# alone still let that case through (1/4 == 0.25, exactly at its cutoff).
_MIN_TYPOSQUAT_NAME_LENGTH = 4


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def registered_domain(url: str) -> str:
    """e.g. https://accounts.login.paypal.com/x -> 'paypal.com'"""
    parts = _extract(url)
    if not parts.domain:
        return ""
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain


_BARE_EMAIL_RE = re.compile(r"^[^\s@/]+@[^\s@/]+\.[^\s@/]+$")


def looks_like_bare_email(raw: str) -> bool:
    """True if `raw` (the raw user input, BEFORE any "https://" prefix is
    added) is shaped like a plain email address rather than a URL -- e.g.
    "verify@openai.com" pasted into the URL checker by mistake. Caught
    live: "noreply@email.openai.com" silently became the URL
    "https://noreply@email.openai.com", which parses as host
    "email.openai.com" with userinfo "noreply" -- a real but confusing
    result for someone who meant to check an email address, not a URL.

    Deliberately narrow: only matches when the *entire* trimmed input is
    local@domain.tld with no slashes anywhere, so a real URL that happens
    to contain "@" (a deliberately-constructed "https://user@host.com"
    with credentials, or a path segment like "/page@2x.jpg") is never
    misclassified -- those always contain "://" or "/", which this pattern
    excludes.
    """
    return bool(_BARE_EMAIL_RE.match(raw.strip()))


def looks_like_url(raw: str) -> bool:
    """True if `raw` has URL structure (a scheme or a path) rather than
    being a bare domain or email address -- e.g. a full link pasted into
    the Email Domain Checker. A bare domain/email never legitimately
    contains "/" or "://".
    """
    value = raw.strip()
    return "://" in value or "/" in value


def is_checkable_web_url(url: str) -> bool:
    """False for inputs that survive naive "prepend https://" handling but
    aren't actually a web URL the rest of this app's pipeline can
    meaningfully assess -- caught live via three cases that all returned a
    fabricated-looking "safe, 83% confident" verdict instead of a clear
    rejection:

    - A non-http(s) scheme (e.g. "ftp://example.com", "file:///etc/passwd")
      -- this app only knows how to assess web pages, not other protocols.
    - "javascript:alert(1)" -- has no "://" at all, so the caller's own
      "prepend https://" step turns it into "https://javascript:alert(1)",
      which *parses* (host "javascript", "alert(1)" mistaken for a port)
      without ever being a real address.
    - "data:text/html,..." -- same shape of problem as the above.

    Must be called on the URL *after* any https:// prefixing the caller
    already applied, so both "explicit bad scheme" and "prefixing produced
    nonsense" are caught by the same two checks below.
    """
    scheme = urlsplit(url).scheme
    if scheme not in ("http", "https"):
        return False
    if has_ip_address(url):
        return True
    parts = _extract(url)
    return bool(parts.domain) and bool(parts.suffix)


def has_ip_address(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return bool(
        _IPV4_RE.match(host) or _IPV4_HEX_RE.match(host) or (":" in host and _IPV6_RE.match(host))
    )


def url_length(url: str) -> int:
    return len(url)


def uses_url_shortener(url: str) -> bool:
    parts = _extract(url)
    domain = f"{parts.domain}.{parts.suffix}".lower()
    return domain in _SHORTENER_DOMAINS


def has_at_symbol(url: str) -> bool:
    return "@" in url


def has_double_slash_redirect(url: str) -> bool:
    """'//' appearing anywhere after the scheme separator is a classic
    open-redirect / hidden-destination trick."""
    scheme_sep = url.find("://")
    start = scheme_sep + 3 if scheme_sep != -1 else 0
    return "//" in url[start:]


def subdomain_count(url: str) -> int:
    parts = _extract(url)
    if not parts.subdomain:
        return 0
    return parts.subdomain.count(".") + 1


def uses_https(url: str) -> bool:
    return urlsplit(url).scheme.lower() == "https"


def digit_ratio_in_domain(url: str) -> float:
    parts = _extract(url)
    domain = parts.domain
    if not domain:
        return 0.0
    digits = sum(ch.isdigit() for ch in domain)
    return digits / len(domain)


def domain_entropy(url: str) -> float:
    parts = _extract(url)
    return _shannon_entropy(parts.domain)


def has_suspicious_tld(url: str) -> bool:
    parts = _extract(url)
    return parts.suffix.lower() in _SUSPICIOUS_TLDS


def brand_typosquat_distance(url: str) -> int:
    """Minimum edit distance from the registrable domain's name to any
    known brand name. A small nonzero distance (e.g. 1-2) on a domain that
    is NOT the real brand domain is a strong phishing signal; 0 means it
    either *is* the brand or shares its exact name (further disambiguated
    by the caller using the full registered domain, not just this number).
    """
    parts = _extract(url)
    name = parts.domain.lower()
    if not name:
        return -1
    return min(_levenshtein(name, brand) for brand in _BRAND_DOMAINS)


def is_exact_brand_domain(url: str) -> bool:
    return known_brand_slug(url) is not None


def _levenshtein_ops(a: str, b: str) -> list[tuple[str, str, str]]:
    """Minimal edit operations that turn `a` into `b`, via the standard
    Levenshtein DP table's backtrace. Each op is (kind, from_char, to_char)
    where kind is "substitute", "delete" (from_char removed from `a`), or
    "insert" (to_char added, not present in `a`). No position index is
    returned -- domain names are short enough that "the letter X" already
    unambiguously identifies it for the single-edit case this is actually
    used for (typosquat_target only calls this when distance <= 2).
    """
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i
    for j in range(m + 1):
        dp[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)

    ops: list[tuple[str, str, str]] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and a[i - 1] == b[j - 1]:
            i, j = i - 1, j - 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            ops.append(("substitute", a[i - 1], b[j - 1]))
            i, j = i - 1, j - 1
        elif i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append(("delete", a[i - 1], ""))
            i -= 1
        else:
            ops.append(("insert", "", b[j - 1]))
            j -= 1
    ops.reverse()
    return ops


def describe_typosquat_difference(entered_name: str, brand: str) -> str:
    """Plain-language description of exactly how `entered_name` differs
    from `brand` -- turns "this looks like paypal" into "the letter 'l'
    was swapped for '1'", which is the actionable part of the warning:
    without it, a user overlooking a single swapped letter (the whole
    problem in the first place) has no way to tell what to look for.
    """
    ops = _levenshtein_ops(entered_name, brand)
    if len(ops) == 1:
        kind, frm, to = ops[0]
        if kind == "substitute":
            return f'the letter "{frm}" was swapped for "{to}"'
        if kind == "delete":
            return f'an extra letter "{frm}" was added'
        return f'the letter "{to}" is missing'
    return f"{len(ops)} letters differ from the real domain"


@dataclass(frozen=True)
class TyposquatMatch:
    brand: str
    real_domain: str
    # None for the brand-name-stuffing pattern (e.g.
    # "paypal-secure-login.com") -- there's no single "letter swap" to
    # point to there, the whole matched word is the tell.
    diff_description: str | None


def typosquat_target(url: str) -> TyposquatMatch | None:
    """Which brand this domain looks like a lookalike of, for UI display
    (e.g. "You entered X -- this looks like a lookalike of Y"). Distinct
    from `brand_typosquat_distance` (a raw number the model consumes).
    Catches two distinct patterns, both requiring the domain not be the
    real brand domain itself:

    1. Spelling-close lookalikes ("paypa1.com") -- close in absolute edit
       distance AND close relative to the name's length, so a short real
       domain like "app.com" doesn't get flagged just for sharing a short
       prefix with "apple". Candidates are also filtered to brands within
       2 characters of the entered name's length before any distance is
       computed at all: a name can't be a spelling-close lookalike of a
       brand of wildly different length, so this both keeps matching fast
       as the brand list grows and further shrinks false-positive risk
       (fewer, more plausible candidates considered per name).
    2. Brand-name stuffing ("paypal-secure-login.com") -- a known brand
       name appearing as a whole hyphen/underscore-separated word
       alongside other words. This used to be caught only loosely, if at
       all, by a blanket "has a hyphen in the domain" feature -- which
       produces far more false positives today than it used to (hyphens
       are common in ordinary product names now) than true positives, so
       it was dropped in favor of this more precise, brand-specific check.
       Whole-word matching (not a raw substring check) matters here: it
       avoids flagging something like "target-market.com" for containing
       "target" *inside* an unrelated compound... except when "target"
       itself is the whole word, which is exactly the risk with brand
       names that are also common English words -- a known, accepted
       trade-off, same as with any short/common brand name in this list.
    """
    parts = _extract(url)
    name = parts.domain.lower()
    if not name or name in _BRAND_DOMAINS or name in _REAL_DOMAIN_NAMES:
        return None

    words = re.split(r"[-_]", name)
    if len(words) > 1:
        for brand in _BRAND_DOMAINS:
            if brand in words:
                return TyposquatMatch(
                    brand=brand, real_domain=_BRAND_DOMAINS[brand], diff_description=None
                )

    if len(name) < _MIN_TYPOSQUAT_NAME_LENGTH:
        return None

    candidates = [b for b in _BRAND_DOMAINS if abs(len(b) - len(name)) <= 2]
    if not candidates:
        return None
    brand, distance = min(
        ((b, _levenshtein(name, b)) for b in candidates), key=lambda kv: kv[1]
    )
    if distance == 0:
        return None
    longest = max(len(name), len(brand))
    if distance <= 2 and distance / longest <= 0.25:
        return TyposquatMatch(
            brand=brand,
            real_domain=_BRAND_DOMAINS[brand],
            diff_description=describe_typosquat_difference(name, brand),
        )
    return None


@dataclass(frozen=True)
class LexicalFeatures:
    url_length: int
    has_ip_address: bool
    uses_url_shortener: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
    subdomain_count: int
    uses_https: bool
    digit_ratio_in_domain: float
    domain_entropy: float
    has_suspicious_tld: bool
    brand_typosquat_distance: int
    is_exact_brand_domain: bool

    def as_dict(self) -> dict[str, float | int | bool]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def extract_lexical_features(url: str) -> LexicalFeatures:
    return LexicalFeatures(
        url_length=url_length(url),
        has_ip_address=has_ip_address(url),
        uses_url_shortener=uses_url_shortener(url),
        has_at_symbol=has_at_symbol(url),
        has_double_slash_redirect=has_double_slash_redirect(url),
        subdomain_count=subdomain_count(url),
        uses_https=uses_https(url),
        digit_ratio_in_domain=digit_ratio_in_domain(url),
        domain_entropy=domain_entropy(url),
        has_suspicious_tld=has_suspicious_tld(url),
        brand_typosquat_distance=brand_typosquat_distance(url),
        is_exact_brand_domain=is_exact_brand_domain(url),
    )
