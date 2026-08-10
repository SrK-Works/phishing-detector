import { useEffect, useState, type FormEvent } from "react";
import { humanizeFeature } from "./featureLabels";
import type { CheckResponse, StatsResponse } from "./types";

async function checkUrl(url: string): Promise<CheckResponse> {
  const res = await fetch("/api/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `Request failed (${res.status})`);
  }
  return res.json();
}

async function fetchStats(): Promise<StatsResponse> {
  const res = await fetch("/api/stats");
  if (!res.ok) throw new Error("Failed to load stats");
  return res.json();
}

const MISSING_SIGNAL_LABELS: Record<string, string> = {
  domain_age: "domain age",
  page_content: "page content",
};

type Tone = "safe" | "phishing" | "uncertain";

const TONE_HEX: Record<Tone, string> = {
  safe: "#34d399",
  phishing: "#f87171",
  uncertain: "#fbbf24",
};

const TONE_TEXT_CLASS: Record<Tone, string> = {
  safe: "text-emerald-400",
  phishing: "text-red-400",
  uncertain: "text-amber-400",
};

const TONE_BORDER_CLASS: Record<Tone, string> = {
  safe: "border-l-emerald-500",
  phishing: "border-l-red-500",
  uncertain: "border-l-amber-500",
};

function verdictTone(result: CheckResponse): Tone {
  if (result.low_confidence) return "uncertain";
  return result.verdict === "safe" ? "safe" : "phishing";
}

function verdictLabel(result: CheckResponse): string {
  if (result.low_confidence) return "Uncertain";
  return result.verdict === "safe" ? "Looks legitimate" : "Likely phishing";
}

// One shield glyph whose shape changes with the verdict, colored via
// currentColor so it always matches the surrounding tone class.
function ShieldIcon({ tone }: { tone: Tone }) {
  const inner =
    tone === "safe" ? (
      <path d="M9 12.5l2 2 4-4.5" />
    ) : tone === "phishing" ? (
      <path d="M12 8.5v4M12 15.5h.01" />
    ) : (
      <path d="M10 9.3c.3-.9 1.1-1.3 2-1.3 1.1 0 2 .7 2 1.7 0 1.4-2 1.4-2 3M12 15.5h.01" />
    );
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-6 w-6 shrink-0"
    >
      <path d="M12 3l7 3v5c0 4.6-3 8.2-7 10-4-1.8-7-5.4-7-10V6l7-3z" />
      {inner}
    </svg>
  );
}

// A compact ring gauge built from a plain conic-gradient -- no icon/chart
// library needed for a single filled arc.
function ConfidenceGauge({ confidence, tone }: { confidence: number; tone: Tone }) {
  const pct = Math.round(confidence * 100);
  const color = TONE_HEX[tone];
  return (
    <div className="relative h-16 w-16 shrink-0">
      <div
        className="absolute inset-0 rounded-full"
        style={{ background: `conic-gradient(${color} ${pct}%, #374151 0)` }}
      />
      <div className="absolute inset-[3px] rounded-full bg-gray-900 flex items-center justify-center">
        <span className="text-sm font-semibold text-gray-100">{pct}%</span>
      </div>
    </div>
  );
}

function formatAge(days: number): string {
  if (days >= 365) {
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? "" : "s"} old`;
  }
  return `${days} day${days === 1 ? "" : "s"} old`;
}

interface SignalRow {
  label: string;
  value: string;
  known: boolean;
}

// Every one of these is data the backend already computes for every check
// -- this just makes it visible instead of leaving it buried inside the
// verdict/override logic.
function buildSignals(result: CheckResponse): SignalRow[] {
  const contentBlocked = result.missing_signals.includes("page_content");
  return [
    {
      label: "Google Safe Browsing",
      value: !result.safe_browsing_available
        ? "Not checked (no API key configured)"
        : !result.safe_browsing_checked
          ? "Temporarily unavailable (request failed or rate-limited)"
          : result.override_reason === "confirmed_threat"
            ? "Flagged as a known threat"
            : "No known threats found",
      known: result.safe_browsing_checked,
    },
    {
      label: "VirusTotal",
      value: !result.virustotal_available
        ? "Not checked (no API key configured)"
        : !result.virustotal_checked
          ? "No data available (not previously scanned, or the check didn't complete)"
          : result.virustotal_malicious_count && result.virustotal_malicious_count > 0
            ? `Flagged by ${result.virustotal_malicious_count} of ${result.virustotal_total_engines} security vendors`
            : `No vendors flagged it (${result.virustotal_total_engines} checked)`,
      known: result.virustotal_checked,
    },
    {
      label: "Domain resolves",
      value:
        result.dns_resolves == null
          ? "Unknown (lookup didn't complete)"
          : result.dns_resolves
            ? "Yes"
            : "No -- this domain has no active DNS record",
      known: result.dns_resolves != null,
    },
    {
      label: "Site popularity",
      value:
        result.popularity_rank != null
          ? `#${result.popularity_rank.toLocaleString()} most-visited site`
          : "Not among the top 200k most-visited sites",
      known: result.popularity_rank != null,
    },
    {
      label: "Domain age",
      value:
        result.domain_age_days != null
          ? formatAge(result.domain_age_days)
          : "Unknown (registration lookup failed)",
      known: result.domain_age_days != null,
    },
    {
      label: "HTTPS certificate",
      value:
        result.tls_cert_age_days != null
          ? `Valid, issued ${formatAge(result.tls_cert_age_days)}`
          : "Missing or invalid",
      known: result.tls_cert_age_days != null,
    },
    {
      label: "Brand lookalike check",
      value: result.typosquat_target
        ? `Resembles "${result.typosquat_target}"`
        : "No resemblance to known brands",
      known: true,
    },
    {
      label: "Page content",
      value: contentBlocked
        ? "Blocked or unavailable"
        : result.redirect_count > 0
          ? `Analyzed (${result.redirect_count} redirect${result.redirect_count === 1 ? "" : "s"})`
          : "Analyzed",
      known: !contentBlocked,
    },
  ];
}

function ResultSkeleton() {
  return (
    <div className="mt-6 rounded-xl border border-gray-700 bg-gray-800/50 p-5 animate-pulse">
      <div className="flex items-center gap-4">
        <div className="h-16 w-16 rounded-full bg-gray-700" />
        <div className="flex-1 space-y-2">
          <div className="h-4 w-40 rounded bg-gray-700" />
          <div className="h-3 w-56 rounded bg-gray-700" />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<StatsResponse | null>(null);

  const loadStats = () => {
    fetchStats()
      .then(setStats)
      .catch(() => setStats(null));
  };

  useEffect(loadStats, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await checkUrl(url.trim());
      setResult(res);
      loadStats();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center px-4 py-16">
      <div className="w-full max-w-xl">
        <h1 className="text-3xl font-bold text-center text-gray-100">
          URL Safety Checker
        </h1>
        <p className="text-center text-gray-400 mt-2 text-sm">
          Scores a URL with a trained model, cross-checks it against
          brand-lookalike patterns, domain popularity, and Google Safe
          Browsing, then explains its reasoning.
        </p>

        <form onSubmit={onSubmit} className="mt-8 flex gap-2">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com or https://example.com/login"
            className="flex-1 rounded-lg bg-gray-800 border border-gray-700 px-4 py-2.5 text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {loading && (
              <span className="h-3.5 w-3.5 rounded-full border-2 border-white/40 border-t-white animate-spin" />
            )}
            {loading ? "Checking..." : "Check"}
          </button>
        </form>

        {error && (
          <p className="mt-4 text-sm text-red-400 text-center">{error}</p>
        )}

        {loading && !result && <ResultSkeleton />}

        {result && (
          <div
            className={`mt-6 rounded-xl border border-l-4 border-gray-700 ${TONE_BORDER_CLASS[verdictTone(result)]} bg-gray-800/50 p-5`}
          >
            {result.typosquat_target && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                This looks like a lookalike of{" "}
                <strong>{result.typosquat_real_domain ?? `${result.typosquat_target}.com`}</strong>
                {" -- "}
                {result.typosquat_diff
                  ? `${result.typosquat_diff}. Easy to miss at a glance, which is exactly how this kind of phishing works.`
                  : "not the real thing."}
              </div>
            )}
            {result.override_reason === "confirmed_threat" && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                Confirmed malicious by Google Safe Browsing's threat list.
              </div>
            )}
            {result.override_reason === "virustotal_flagged" && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                Flagged as malicious by {result.virustotal_malicious_count} of{" "}
                {result.virustotal_total_engines} security vendors on VirusTotal.
              </div>
            )}
            {result.override_reason === "domain_unreachable" && (
              <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
                This domain does not resolve at all -- there's no live site here
                to inspect, so nothing about it can be confirmed as safe or
                unsafe.
              </div>
            )}
            {result.override_reason === "popular_domain" && (
              <div className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
                This domain ranks #{result.popularity_rank?.toLocaleString()} among the
                world's most-visited sites, which outweighs an otherwise shaky
                signal from our own checks.
              </div>
            )}
            <div className="flex items-center gap-4">
              <ConfidenceGauge confidence={result.confidence} tone={verdictTone(result)} />
              <div className="min-w-0">
                <div className={`flex items-center gap-1.5 font-semibold ${TONE_TEXT_CLASS[verdictTone(result)]}`}>
                  <ShieldIcon tone={verdictTone(result)} />
                  {verdictLabel(result)}
                </div>
                <p className="text-xs text-gray-500 break-all mt-0.5">{result.url}</p>
              </div>
            </div>
            {result.site_description && (
              <div className="mt-4 rounded-lg bg-gray-900/50 p-3">
                <span className="inline-block rounded border border-indigo-500/40 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-300">
                  AI summary
                </span>
                <p className="mt-1.5 text-sm text-gray-300">{result.site_description}</p>
                <p className="mt-1 text-[11px] text-gray-500">
                  Generated from the page's own content -- informational only,
                  not a safety signal.
                </p>
              </div>
            )}

            <div className="mt-5">
              <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">
                Signals checked
              </p>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
                {buildSignals(result).map((s) => (
                  <li key={s.label} className="text-sm flex items-start gap-2">
                    <span
                      className={`mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 ${
                        s.known ? "bg-indigo-400" : "bg-gray-600"
                      }`}
                    />
                    <span className="text-gray-300">
                      <span className="text-gray-500">{s.label}: </span>
                      {s.value}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {result.low_confidence && (
              <p className="mt-3 text-xs text-amber-400">
                This came out close to a coin flip
                {result.missing_signals.length > 0 && (
                  <>
                    {" "}
                    because we couldn't verify{" "}
                    {result.missing_signals
                      .map((s) => MISSING_SIGNAL_LABELS[s] ?? s)
                      .join(" or ")}
                    {" "}
                    (e.g. the site blocked automated checks, or a lookup timed out)
                  </>
                )}
                {" "}-- treat the "{result.verdict === "safe" ? "looks legitimate" : "likely phishing"}" call with caution.
              </p>
            )}

            {(result.reason_narrative || result.reasons.length > 0) && (
              <div className="mt-5">
                <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">
                  Why
                </p>
                {result.reason_narrative && (
                  <p className="text-sm text-gray-300 mb-3">{result.reason_narrative}</p>
                )}
                {result.reasons.length > 0 && (
                  <ul className="space-y-1.5">
                    {result.reasons.map((r) => (
                      <li
                        key={r.feature}
                        className="text-sm text-gray-300 flex items-start gap-2"
                      >
                        <span
                          className={`mt-1 h-1.5 w-1.5 rounded-full shrink-0 ${
                            r.impact >= 0 ? "bg-emerald-400" : "bg-red-400"
                          }`}
                        />
                        {humanizeFeature(r.feature)}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {result.partial && (
              <p className="mt-4 text-xs text-amber-400">
                Some checks (WHOIS/page content) didn't finish in time -- this
                verdict is based on partial data.
              </p>
            )}
            {result.cached && (
              <p className="mt-2 text-xs text-gray-500">
                Result from a previous check within the last 24 hours.
              </p>
            )}
          </div>
        )}

        {stats && (
          <p className="mt-8 text-center text-xs text-gray-500">
            {stats.safe_count} sites checked safe &middot; {stats.phishing_count} flagged as phishing
          </p>
        )}
      </div>
    </div>
  );
}
