# Testing Concepts, Learned From This Project

This exists for one reason: to turn QA/testing vocabulary from something
memorized into something you've actually *done*, using real examples from
building this app. Every concept below points at a real file, test, or bug
from this repo — not a textbook definition. Going forward, whenever we add
tests or track down a bug in this project, expect a callout back to this
doc with the new concept attached.

---

## 1. Testing levels (how big a slice of the system you're testing)

**Unit testing** — testing one function/module in complete isolation, with
all its dependencies faked out.
- *In this project*: `tests/test_lexical.py`, `tests/test_verdict.py`,
  `tests/test_content.py` — pure functions, no network, no database.
  `tests/test_reputation.py` and `tests/test_description.py` go a step
  further: they test functions that *would* call the network (Safe
  Browsing, VirusTotal, Gemini), but the test replaces `requests.post`
  with a fake object (see **Mocking** below) so no real call ever happens.

**Integration testing** — testing that two or more real units work
correctly *together*, not just individually.
- *In this project*: `app/pipeline.py`'s `extract_all_features` runs
  lexical + host + content extraction together and combines the results —
  we don't have a dedicated test file for this specific integration, which
  is a real gap (see §6).

**System testing** — testing the whole application as one thing, the way a
real caller would use it (HTTP in, JSON out), including the database.
- *In this project*: `tests/test_api_smoke.py` — it calls
  `TestClient(app).post("/api/check", ...)`, which exercises routing,
  feature extraction, the trained model, verdict overrides, and SQLite,
  all in one call.

**End-to-end (E2E) testing** — testing the entire real user journey,
usually through the actual UI, sometimes across real external systems too.
- *In this project*: this is what I've been doing manually with the
  Chrome browser tool — typing a URL into the actual React app, clicking
  Check, and confirming the rendered page looks right. We have zero
  *automated* E2E tests right now (no Playwright/Cypress suite driving the
  frontend) — another real, worth-naming gap.

---

## 2. Testing types (what aspect you're checking)

**Functional testing** — does it do the right thing per the requirement?
- *In this project*: almost everything in `tests/` is functional —
  e.g. `test_typosquat_target_flags_close_lookalike` asserts
  `typosquat_target("https://paypa1.com/login") == "paypal"`.

**Non-functional testing** — does it do the right thing *well enough*
(speed, security, reliability), separate from whether the logic is correct?
- **Performance**: `check_timeout_seconds` / `network_timeout_seconds` in
  `config.py` exist because a WHOIS lookup taking 8 seconds is a
  performance failure even if the eventual answer would've been correct.
- **Security**: `app/security.py`'s SSRF guard (blocking requests to
  private/loopback/metadata IPs) and its test file are pure non-functional
  security testing — they don't care what the phishing model says, only
  whether the server can be tricked into fetching something dangerous.
- **Usability**: this is closer to what the whole "Uncertain" badge / plain
  language "Why" narrative effort was about — technically correct output
  that's still a usability failure if a normal person can't understand it.

---

## 3. Testing techniques

**Manual testing** — a human explores the app and judges the result.
**Automated testing** — code checks the result, repeatably, without a human.
- *In this project*: `pytest` (73 tests as of the VirusTotal work) is
  automated. Every time I've opened Chrome and typed a URL in to eyeball
  the result, that was manual testing.

**Black-box testing** — testing through the public interface only, with no
knowledge of (or reliance on) internal implementation.
**White-box testing** — testing with full knowledge of the internals,
sometimes calling internal functions directly.
- *In this project*: `test_api_smoke.py` is black-box — it only knows
  "POST this URL, expect this shape of JSON back." `test_content.py`
  calling the private `_is_external()` helper directly is white-box — it
  reaches straight into an implementation detail most callers never touch.

**Positive testing** — feeding valid/expected input and checking for the
correct, expected outcome.
**Negative testing** — feeding invalid, unexpected, or hostile input and
checking the app *fails correctly* (rejects it, degrades gracefully, etc.)
rather than crashing.
- *In this project*: `test_check_rejects_empty_url` (a blank URL should
  get a 422, not a 500) is negative testing. Every SSRF test that asserts
  a private IP gets *blocked* is also negative testing — we're proving bad
  input is handled safely, not proving a feature works.

**Boundary value analysis** — bugs love to hide exactly at the edge of a
condition (`<` vs `<=`, `== 0` vs `> 0`), so you deliberately test values
sitting right on that line.
- *In this project*: this is **exactly** what the `ets.org` bug was. The
  old rule was "flag as typosquat if `distance / longest <= 0.25`."
  `"ets"` vs `"etsy"` computes to *precisely* `1/4 = 0.25` — sitting right
  on the boundary, not comfortably inside or outside it. The fix
  (`test_typosquat_target_ignores_short_name_even_at_edit_distance_one`)
  is a boundary-value regression test: it locks in the exact edge case
  that broke, so it can never silently regress.

**Exploratory testing** — testing without a pre-written script, actively
probing based on what you notice as you go.
- *In this project*: when you pasted `ereg.ets.org` because you personally
  had it bookmarked, that was exploratory testing — an unscripted,
  real-world input nobody had written a test case for yet, which is
  exactly the kind of input that finds bugs scripted tests miss.

**Smoke testing** — a quick, shallow check that the build isn't
*fundamentally* broken before doing anything deeper ("did it even turn
on?"). Breadth over depth.
- *In this project*: every time I restarted the backend after a change,
  the very next thing I did was `curl /api/stats` or `/api/check` once,
  just to confirm the server came up and answered *something* sane before
  moving on. That's a smoke test — I wasn't checking correctness yet, just
  "is it alive."

**Sanity testing** — a quick, *narrow* check that one specific fix works,
after a small change, without re-running everything.
- *In this project*: right after the `ets.org` fix, I ran one `curl`
  against that exact URL to confirm it now says "safe" — I didn't
  re-verify every other URL we'd ever tested. That's sanity testing: deep
  on one thing, narrow in scope.

**Regression testing** — re-running the *existing* test suite after a
change, to make sure something that used to work didn't just break.
Breadth over depth again, but repeated every time, not just once.
- *In this project*: this is the "run the full 73-test suite" step I do
  after *every single change* in this project, without exception. It's
  regression testing specifically because it's not testing the new thing —
  it's re-checking everything old still holds.

**Retesting** — literally re-running the *one test that previously failed*
against the fix, to confirm that specific defect is gone. Easy to confuse
with regression testing, but it's the opposite scope (one known failure,
not the whole suite).
- *In this project*: after fixing the `ets.org` bug, re-running
  `test_typosquat_target_ignores_short_name_even_at_edit_distance_one`
  specifically is retesting. Then running the *whole suite* afterward is
  regression testing. Interviewers love this exact distinction.

---

## 4. Bugs, severity, priority, and test cases

**Defect/bug** — a gap between what the software actually does and what it
was supposed to do.
- *In this project*: the `ets.org` false positive, the `paypa1.com`
  contradiction (red typosquat banner next to a confident green "safe"
  badge), and the Gemini "thinking mode eats the whole token budget"
  incident were all real bugs found during this rebuild.

**Severity** — *how bad* the bug's impact is on the system/user, from a
purely technical/functional standpoint. Independent of how urgently it
needs fixing.
**Priority** — *how soon* it should be fixed, based on business/user
impact, deadlines, and context. Independent of how technically severe it
is.

These two are graded separately and interviewers specifically probe
whether you understand they're **not the same axis**:

| | High severity | Low severity |
|---|---|---|
| **High priority** | Core feature completely broken for everyone (e.g. `/api/check` 500s on every request) — fix now. | A typo in the verdict label on the homepage right before a big demo — technically trivial, but very visible right now. |
| **Low priority** | A rare crash in an admin-only export tool nobody uses yet — bad if it happens, but it doesn't happen often and can wait. | A slightly misaligned pixel in a footer nobody's complained about — fine to leave in the backlog indefinitely. |

- *In this project*: the `ets.org` bug was arguably **medium-high
  severity** (a real, legitimate, decades-old site gets called "phishing"
  — that's the core promise of the app failing) and **high priority**
  (you hit it on your own bookmarked site and reported it immediately —
  real user impact, right now). The pre-existing `FormEvent` deprecation
  warning I fixed in passing was **low severity, low priority** — it
  never affected behavior, just code cleanliness.

**Bug life cycle** (the states a bug moves through in a tracker like Jira):
`New → Assigned → In Progress → Fixed → Retest → Closed` (or `Reopened` if
retesting shows it's still broken). We don't use a formal tracker in this
project (it's just you and me in chat), but every bug we've fixed followed
this shape informally: you reported it (**New**), I investigated
root-cause before touching code (**Assigned/In Progress** — and this
"investigate before fixing" habit you insisted on from the start is
exactly what a good QA/dev process looks like), I applied and explained
the fix (**Fixed**), then I re-ran the specific test plus the full suite
(**Retest**), and only called it done once both passed (**Closed**).

**Test case anatomy** — a well-written test case has: an ID, a
precondition, the exact steps, the *expected* result, and (when actually
run) the *actual* result — pass if they match, fail if they don't.
- *In this project*, `test_typosquat_target_ignores_short_name_even_at_edit_distance_one`
  written in plain English would be:
  - **Precondition**: the typosquat brand list includes "etsy"
  - **Steps**: call `typosquat_target("https://ets.org/")`
  - **Expected result**: `None` (not a lookalike)
  - **Actual result** (before the fix): `"etsy"` — **FAIL**
  - **Actual result** (after the fix): `None` — **PASS**

---

## 5. Automation-specific concepts

**Mocking / stubbing** — replacing a real dependency (a network call, a
database, the system clock) with a fake stand-in you control, so the test
is fast, reliable, and doesn't actually hit the internet.
- *In this project*: every test in `test_reputation.py` and
  `test_description.py` uses `unittest.mock.patch` to replace
  `requests.post`/`requests.get` with a fake response object. Without
  this, our test suite would make real calls to Google/VirusTotal/Gemini
  every time it ran — slow, flaky, and burning real API quota just to run
  `pytest`.

**Test fixtures** — reusable setup (and teardown) shared across tests, so
each test doesn't repeat the same boilerplate.
- *In this project*: `test_api_smoke.py`'s `client` fixture builds one
  `TestClient(app)` and shares it across all three tests in that file
  instead of re-creating the app per test.

**Test coverage** — how much of the actual code/behavior your tests
exercise. High coverage numbers can still hide bad tests (you can call a
function without checking its output means anything), so it's a useful
signal, never proof of correctness on its own.
- *In this project*: we have strong coverage on the pure logic
  (`lexical.py`, `verdict.py`) and the reputation/description integrations
  (all mocked), but essentially **zero automated coverage on the React
  frontend** — every UI check so far has been manual. That's a real,
  nameable gap, not a hidden one.

---

## 6. Honest gaps in this project's test strategy (good interview material)

Being asked "what would you improve about this test suite?" is common —
here's the real, unpadded answer for this project:
- No automated frontend tests (no Vitest/RTL component tests, no
  Playwright/Cypress E2E) — every UI verification has been manual.
- No CI pipeline (tests only run when I manually invoke `pytest` locally)
  — nothing stops a broken commit from being made, only from being
  *shipped* if someone remembers to run tests first.
- `test_api_smoke.py` makes real network calls and is explicitly marked
  "slow/flaky-tolerant by design" — a more mature suite would isolate that
  behind a marker (e.g. `@pytest.mark.network`) so CI could skip it by
  default and only run it on demand.
- No dedicated integration test for `app/pipeline.py` itself (only
  covered indirectly through the system-level smoke test).
