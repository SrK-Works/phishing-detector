import { useState, type FormEvent } from "react";
import { humanizeFeature } from "../featureLabels";
import { checkUrl } from "../lib/api";
import type { CheckResponse } from "../types";
import {
  ConfidenceGauge,
  HowItWorks,
  RemediationTips,
  ResultSkeleton,
  ShieldIcon,
  SignalList,
  TONE_BORDER_CLASS,
  TONE_TEXT_CLASS,
  formatAge,
  verdictLabel,
  verdictTone,
  type SignalRow,
} from "./shared";

const URL_REMEDIATION_TIPS = [
  "Don't enter a password, OTP, or payment details on this page.",
  "Don't download anything from it.",
  "If you already entered something there, change that password now and keep an eye on the account.",
  "Close the tab -- don't follow any \"continue\" or \"verify\" links on it.",
];

const MISSING_SIGNAL_LABELS: Record<string, string> = {
  domain_age: "domain age",
  page_content: "page content",
};

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

export default function UrlChecker({ onChecked }: { onChecked?: () => void }) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await checkUrl(url.trim());
      setResult(res);
      onChecked?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <h1 className="text-3xl font-bold text-center text-gray-100">URL Safety Checker</h1>
      <p className="text-center text-gray-400 mt-2 text-sm">
        Scores a URL with a trained model, cross-checks it against
        brand-lookalike patterns, domain popularity, and Google Safe
        Browsing, then explains its reasoning.
      </p>
      <HowItWorks>
        <p>
          Paste any web address you're unsure about. We check whether it's
          trying to imitate a real company's domain (like{" "}
          <span className="text-gray-100">paypa1.com</span> instead of{" "}
          <span className="text-gray-100">paypal.com</span>), how old and
          established the domain is, whether it has a valid security
          certificate, and cross-reference it against Google Safe Browsing
          and VirusTotal's databases of known-malicious sites.
        </p>
        <p>
          A trained model combines all of these signals into a verdict, and
          the "Signals checked" and "Why" sections below show exactly which
          ones drove the call -- so you're never just told "trust us."
        </p>
      </HowItWorks>

      <form onSubmit={onSubmit} className="mt-8 flex flex-col sm:flex-row gap-2">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="example.com or https://example.com/login"
          className="flex-1 min-w-0 rounded-lg bg-gray-800 border border-gray-700 px-4 py-2.5 text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <button
          type="submit"
          disabled={loading}
          className="flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
        >
          {loading && (
            <span className="h-3.5 w-3.5 rounded-full border-2 border-white/40 border-t-white animate-spin" />
          )}
          {loading ? "Checking..." : "Check"}
        </button>
      </form>

      {error && <p className="mt-4 text-sm text-red-400 text-center">{error}</p>}

      {loading && !result && <ResultSkeleton />}

      {result && (
        <div
          className={`mt-6 rounded-xl border border-l-4 border-gray-700 ${TONE_BORDER_CLASS[verdictTone(result)]} bg-gray-800/50 p-5`}
        >
          {result.known_brand_display_name && (
            <div className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
              This is the real, verified domain for <strong>{result.known_brand_display_name}</strong>.
            </div>
          )}
          {result.typosquat_target && (
            <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              This looks like a fake domain mimicking{" "}
              <strong>{result.typosquat_brand_display ?? result.typosquat_target}</strong> -- their real
              domain is <strong>{result.typosquat_real_domain ?? `${result.typosquat_target}.com`}</strong>
              {". "}
              {result.typosquat_diff
                ? `${result.typosquat_diff}. Easy to miss at a glance, which is exactly how this kind of phishing works.`
                : "This is not the real thing."}
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
            <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Signals checked</p>
            <SignalList signals={buildSignals(result)} />
          </div>

          {result.low_confidence && (
            <p className="mt-3 text-xs text-amber-400">
              This came out close to a coin flip
              {result.missing_signals.length > 0 && (
                <>
                  {" "}
                  because we couldn't verify{" "}
                  {result.missing_signals.map((s) => MISSING_SIGNAL_LABELS[s] ?? s).join(" or ")}{" "}
                  (e.g. the site blocked automated checks, or a lookup timed out)
                </>
              )}{" "}
              -- treat the "{result.verdict === "safe" ? "looks legitimate" : "likely phishing"}" call with caution.
            </p>
          )}

          {(result.reason_narrative || result.reasons.length > 0) && (
            <div className="mt-5">
              <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Why</p>
              {result.reason_narrative && (
                <p className="text-sm text-gray-300 mb-3">{result.reason_narrative}</p>
              )}
              {result.reasons.length > 0 && (
                <ul className="space-y-1.5">
                  {result.reasons.map((r) => (
                    <li key={r.feature} className="text-sm text-gray-300 flex items-start gap-2">
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

          {result.verdict === "phishing" && <RemediationTips tips={URL_REMEDIATION_TIPS} />}

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
    </>
  );
}
