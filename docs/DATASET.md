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

Current snapshot: 600 rows, balanced 300/300, rebuilt 2026-08-08 (three
times the same day -- see bugs #5-#7 below).

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

5. **WHOIS timeout budget too tight.** `network_timeout_seconds` was 2.0s,
   but a real WHOIS round-trip regularly takes 1.5-2.0s -- right on the
   edge, so lookups flakily timed out and silently dropped domain-age
   signal. A live check of `usvisascheduling.com` (a legitimate US visa
   scheduling site) landed at 52.7% phishing -- a near coin-flip caused
   entirely by missing data (WHOIS timeout + the site's bot-protection
   blocking our content fetch with a 403), not by anything suspicious about
   the site. Fixed by raising the timeout to 3.5s/6.0s. Also added a
   `host_whois_missing` indicator feature so the model can tell "we don't
   know" apart from a median-imputed guess, and a `low_confidence` flag
   (probability within 0.15 of the 0.5 boundary) surfaced in the API/UI so
   a coin-flip verdict is shown as "Uncertain" instead of with the same
   visual confidence as a decisive call.

6. **Zero legit training URLs had a path.** Every legit URL (Tranco domains
   and the hardcoded brand list) was a bare `https://domain.com` with no
   path, while real phishing-feed URLs virtually always have one --
   phishing kits use realistic-looking paths. The model learned raw
   `url_length` as a phishing proxy and confidently misflagged completely
   ordinary URLs with paths, e.g. `accounts.google.com/signin` at 99.7%
   phishing. Fixed by mixing a pool of realistic paths/query strings into
   legit training URLs (`_with_random_path` in `build_dataset.py`) so the
   length distributions actually overlap. This is a mitigation, not a full
   fix -- see the first known limitation below, which is the same root
   cause with synthetic rather than real paths.

7. **`content_external_resource_ratio`/`external_anchor_ratio` conflated a
   site's own CDN infrastructure with truly foreign domains, and
   `has_hyphen_in_domain` was a blunt, increasingly outdated proxy for
   brand impersonation.** Both features compared against the page's
   *registrable domain* only, so a page loading assets from a sibling
   domain it also owns (Google's `gstatic.com`, Wikipedia's
   `wikimedia.org`) scored identically to a phishing page pulling scripts
   from an unrelated attacker domain -- confirmed as the actual driver
   behind `accounts.google.com/signin` scoring 99.7% legit turning into a
   confident *phishing* call once bug #6 was fixed (SHAP showed
   `content_external_resource_ratio` as the top reason, not URL length).
   Separately, `has_hyphen_in_domain` increasingly flags ordinary modern
   product names (hyphens are common in startup branding today) far more
   than it catches real phishing, and its one genuinely useful case --
   brand-name stuffing like `paypal-secure-login.com` -- is caught more
   precisely by a dedicated check anyway. Fixed by (a) excluding a curated
   list of known CDN/sibling-infra domains from the "external" count in
   `content.py`, and (b) dropping `has_hyphen_in_domain` entirely in favor
   of a whole-word brand-name match added to `typosquat_target`
   (`app/features/lexical.py`), which routes through the same rule-based
   override as other typosquat detection rather than diluted ML training.
   Confirmed fix: `accounts.google.com/signin` now scores 79.7% legit from
   the raw model alone, no override needed.

8. **`registered_domain()` misparsed India's `.bank.in`/`.fin.in` as a
   single shared entity, letting a completely fake subdomain inherit a
   real bank's popularity.** These are RBI/NIXI-launched multi-tenant
   namespaces (banks/NBFCs each register directly under them, e.g.
   `au.bank.in`) -- the same shape as `github.io`, but not yet tracked by
   the bundled Public Suffix List snapshot at all (not even in its
   "private" section, unlike bug #4's fix). Without knowing this,
   `yonosbi.bank.in` -- a domain that doesn't even resolve -- parsed as
   domain=`bank`, suffix=`in`, making its "registrable domain" the shared
   `bank.in`, which is itself real, popular, and Tranco-ranked (#6,369).
   The popularity override then confidently called a non-existent domain
   "safe". Found via a user testing a real-world lookalike URL, not
   synthetic data. Fixed with `extra_suffixes=["bank.in", "fin.in"]` on
   the shared `tldextract` instance -- the direct extension of bug #4's
   fix to a namespace PSL itself doesn't cover.

## Known limitations (not yet fixed)

- **A domain that fails to resolve at all can still score confidently
  "safe" from the raw model.** `yonosbi.bank.in` (bug #8 above) has
  `host_dns_resolves=False` -- there is no live site, at all -- yet the
  calibrated model alone still put it at ~87% legit. Training data is the
  likely cause: legit rows (from Tranco) are by definition live sites, and
  phishing-feed rows are typically captured while still active, so the
  model has seen very few real examples of "this domain doesn't resolve"
  in either class and has little learned signal for it. A domain that
  can't be reached can't be verified as legitimate by any means, so this
  arguably deserves its own rule-based override (independent of
  popularity/WHOIS) rather than being left to the ML model's guess --
  flagged here rather than fixed, since it's a distinct question from the
  bank.in bug that surfaced it.

- **Synthetic paths are a stand-in for real deep links.** Bug #6's fix
  reduces the length-based bias but the paths are drawn from a fixed
  20-item pool, not scraped from the real site -- so the model still has
  no signal about what a *specific* domain's real deep links look like.
  Fixing this properly means sampling real deep links per domain, not
  synthetic ones.
- **Small dataset makes rare combinations unreliable.** A domain that is
  both decades-old *and* one edit away from a known brand (e.g. an old,
  opportunistically-registered `paypa1.com`) is a combination the 600-row
  dataset has few or no examples of, so the model's own probability for
  cases like this can't be trusted -- it scored one such domain 95.7%
  legit. The independent, rule-based `typosquat_target` check (not part of
  the ML model at all) still flags it correctly regardless of what the
  model's confidence says, which is why that check exists as a separate
  signal rather than only as a model feature. Scaling up training data
  volume is the real fix.
- **Shortened URLs are only as good as the redirect chain we can follow.**
  `bit.ly` itself is a legitimate, decades-old domain, so a shortener link
  that doesn't actually resolve to anything won't get flagged just for
  being a shortener -- the model (correctly) needs the destination content
  to judge the destination, not the shortener's own reputation.
- **Dataset is small (600 rows).** Solid enough to validate the pipeline
  end-to-end and catch the bugs above, but not enough for a defensible
  accuracy claim. Scaling up needs either paid feed access or accumulating
  daily snapshots over time. `app/model/train.py`'s cross-validated model
  selection (see ARCHITECTURE.md's "Data & training" section) exists
  specifically because a single train/test split on this little data is
  too noisy to trust on its own -- CV doesn't fix a small dataset, it just
  stops the model-selection step from lying about how sure it is.
