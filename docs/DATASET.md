# Dataset & Methodology

## Sources

- **Legit**: [Tranco](https://tranco-list.eu)'s daily top-1M domain list (the
  research-standard replacement for Alexa rank, which shut down in 2022),
  sampled from the top 50k, plus every domain used in
  `app/features/lexical.py`'s brand/typosquat list (see below for why).
- **Phishing**: [PhishTank](https://phishtank.org)'s verified feed and
  [OpenPhish](https://openphish.com)'s public feed. Both are free but small:
  PhishTank rate-limits unauthenticated bulk downloads (~75 requests / 3
  days), and OpenPhish's free feed caps out around 300 live URLs at any
  given time. A production build would register for PhishTank API access
  and/or pay for OpenPhish's full feed to get real volume.

Current snapshot: 600 rows, balanced 300/300, built 2026-08-08.

## Feature extraction

Every URL goes through `app/pipeline.py`: instant lexical features always,
plus host (WHOIS/DNS/TLS) and content (page fetch) features under a shared
time budget, run concurrently. Missing values (`None`) come from real
failures -- dead domains, WHOIS timeouts, unfetchable pages -- and are
median-imputed at training time, not dropped.

## Bugs found and fixed while building this dataset

Worth documenting because each one silently taught the model something
false, and none of them would show up as a training/test split metric
problem -- ROC-AUC looked fine (0.97+) at every stage, including the buggy
ones. They only surfaced by testing the trained model against real URLs
outside the synthetic dataset.

1. **Time-budget starvation asymmetry.** `pipeline.py` originally waited on
   the WHOIS/DNS future for the *entire* timeout budget before even checking
   the content-fetch future's remaining time. Dead phishing domains fail
   DNS/connect almost instantly, freeing the budget for content fetching;
   live legit domains take real time, which starved content extraction on
   exactly the legit class. Fixed by waiting on both futures concurrently
   with `concurrent.futures.wait(...)` against one shared deadline. Also
   found `host.py` ran WHOIS and the TLS handshake sequentially (up to ~2x
   the intended timeout) -- parallelized those too.

2. **No subdomain variety in legit examples.** Tranco only lists apex
   domains (`google.com`, never `www.google.com`), so 100% of legit training
   rows had `subdomain_count == 0` while most phishing URLs naturally have
   one. The model learned "has a subdomain -> phishing" and flagged
   `www.google.com` as phishing at 80% confidence. Fixed by randomly mixing
   in `www.`-prefixed variants for legit domains (`build_dataset.py`).

3. **No real brand examples in legit training data.** A random 300-domain
   sample of the top 50k essentially never includes the ~24 specific brand
   domains (`google.com`, `paypal.com`, ...) used by the typosquat-distance
   feature. The model never saw a legit example with
   `brand_typosquat_distance == 0`, only phishing examples impersonating a
   brand at distance 1-2, and generalized "close to a known brand" as
   universally suspicious -- misflagging the real brand domains themselves.
   Fixed by explicitly including every brand domain (apex + `www.`) as a
   guaranteed legit example.

4. **Multi-tenant hosting suffixes misparsed.** `tldextract` only recognizes
   official ICANN TLDs unless `include_psl_private_domains=True` is set. Without
   it, `evil-user.github.io` parses as domain=`github`, suffix=`io` --
   exactly matching the "github" brand entry and marking obvious phishing
   pages as an exact brand match. Fixed by enabling PSL private-domain
   parsing, so the *subdomain* (the actual attacker-controlled part) is
   treated as the registrable identity on platforms like GitHub Pages,
   Netlify, Vercel, Blogspot, and S3-hosted sites -- which is also just
   correct, since phishing kits are commonly hosted on exactly these free
   platforms.

## Known limitations (not yet fixed)

- **Deep-linked legit URLs are underrepresented.** Training legit URLs are
  almost all apex/root pages; a real, legitimate deep link
  (`en.wikipedia.org/wiki/Phishing`) can get misjudged as suspicious mostly
  on `url_length`, since the model has little legit-with-a-long-path signal
  to weigh against it. Fixing this properly means sampling real deep links
  per domain, not just the homepage.
- **Shortened URLs are only as good as the redirect chain we can follow.**
  `bit.ly` itself is a legitimate, decades-old domain, so a shortener link
  that doesn't actually resolve to anything won't get flagged just for
  being a shortener -- the model (correctly) needs the destination content
  to judge the destination, not the shortener's own reputation.
- **Dataset is small (600 rows).** Solid enough to validate the pipeline
  end-to-end and catch the bugs above, but not enough for a defensible
  accuracy claim. Scaling up needs either paid feed access or accumulating
  daily snapshots over time.
