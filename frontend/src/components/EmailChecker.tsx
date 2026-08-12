import { useState, type FormEvent } from "react";
import { checkEmail } from "../lib/api";
import type { EmailCheckResponse } from "../types";
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

const LABELS = { safe: "Looks legitimate", phishing: "Likely suspicious" };

const EMAIL_REMEDIATION_TIPS = [
  "Don't click any links or open attachments in this email.",
  "Don't reply to it.",
  "Verify by contacting the company directly through their official website or a phone number you already know -- not one from this email.",
  "If the company has a security/phishing-report address, forward it there, then delete it.",
];

// The scorer's own weighted signals double as the "why" here -- unlike the
// URL checker there's no separate SHAP/narrative layer, since this is a
// transparent rule tally, not a model.
function buildEmailSignals(result: EmailCheckResponse): SignalRow[] {
  return [
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
      label: "Mail server (MX)",
      value:
        result.mx_present == null
          ? "Unknown (lookup didn't complete)"
          : result.mx_present
            ? "Configured"
            : "None -- this domain can't actually receive mail",
      known: result.mx_present != null,
    },
    {
      label: "SPF record",
      value: result.spf_present == null ? "Unknown" : result.spf_present ? "Present" : "Missing",
      known: result.spf_present != null,
    },
    {
      label: "DMARC record",
      value: result.dmarc_present == null ? "Unknown" : result.dmarc_present ? "Present" : "Missing",
      known: result.dmarc_present != null,
    },
    {
      label: "Domain age",
      value: result.domain_age_days != null ? formatAge(result.domain_age_days) : "Unknown (registration lookup failed)",
      known: result.domain_age_days != null,
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
      label: "Brand lookalike check",
      value: result.typosquat_target ? `Resembles "${result.typosquat_target}"` : "No resemblance to known brands",
      known: true,
    },
    {
      label: "Google Safe Browsing",
      value: !result.safe_browsing_available
        ? "Not checked (no API key configured)"
        : !result.safe_browsing_checked
          ? "Temporarily unavailable"
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
          ? "No data available"
          : result.virustotal_malicious_count && result.virustotal_malicious_count > 0
            ? `Flagged by ${result.virustotal_malicious_count} of ${result.virustotal_total_engines} security vendors`
            : `No vendors flagged it (${result.virustotal_total_engines} checked)`,
      known: result.virustotal_checked,
    },
    {
      label: "HTTPS",
      value: result.has_valid_https ? "Valid certificate" : "Missing or invalid",
      known: result.has_valid_https != null,
    },
  ];
}

export default function EmailChecker({ onChecked }: { onChecked?: () => void }) {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<EmailCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await checkEmail(email.trim());
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
      <h1 className="text-3xl font-bold text-center text-gray-100">Email Domain Checker</h1>
      <p className="text-center text-gray-400 mt-2 text-sm">
        Checks whether an email's sending domain is configured the way a
        real organization's mail domain would be -- DNS, mail authentication
        records, domain age, and brand-lookalike patterns. Rule-based, not a
        machine-learning model.
      </p>
      <HowItWorks>
        <p>
          Got a suspicious email -- a "you've been shortlisted" recruitment
          message, a fake payment request? Copy just the sender's email
          address, no need to click anything in the message itself. We pull
          out the domain (the part after @) and check whether it matches a
          real company's domain exactly, or looks like a close copy of one
          (e.g. <span className="text-gray-100">cognigant.com</span> vs{" "}
          <span className="text-gray-100">cognizant.com</span> -- a single
          swapped letter). If we recognize the company being impersonated,
          we'll name it and show you their real domain.
        </p>
        <p>
          We also check things a scammer's domain often gets wrong: can it
          actually receive mail, is it set up with the authentication
          records (SPF, DMARC) a real company's mail system would have, and
          how old is it. There's no machine-learning model behind this one
          -- just a transparent checklist of signals, shown to you exactly
          as we weighed them.
        </p>
      </HowItWorks>

      <form onSubmit={onSubmit} className="mt-8 flex flex-col sm:flex-row gap-2">
        <input
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="support@yourbank.com or yourbank.com"
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
          {result.override_reason === "known_brand_domain" && result.known_brand_display_name && (
            <div className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
              This is the real, verified email domain for{" "}
              <strong>{result.known_brand_display_name}</strong>.
            </div>
          )}
          {result.typosquat_target && (
            <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              This looks like a fake email pretending to be from{" "}
              <strong>{result.typosquat_brand_display ?? result.typosquat_target}</strong> -- their real
              email domain is{" "}
              <strong>{result.typosquat_real_domain ?? `${result.typosquat_target}.com`}</strong>
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
          <div className="flex items-center gap-4">
            <ConfidenceGauge confidence={result.confidence} tone={verdictTone(result)} />
            <div className="min-w-0">
              <div className={`flex items-center gap-1.5 font-semibold ${TONE_TEXT_CLASS[verdictTone(result)]}`}>
                <ShieldIcon tone={verdictTone(result)} />
                {verdictLabel(result, LABELS)}
              </div>
              <p className="text-xs text-gray-500 break-all mt-0.5">{result.domain}</p>
              <p className="text-[11px] text-gray-500 mt-0.5">Risk score: {result.score}/100</p>
            </div>
          </div>

          <div className="mt-5">
            <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Signals checked</p>
            <SignalList signals={buildEmailSignals(result)} />
          </div>

          {result.low_confidence && (
            <p className="mt-3 text-xs text-amber-400">
              This came out close to a coin flip -- treat the "
              {result.verdict === "safe" ? "looks legitimate" : "likely suspicious"}" call with caution.
            </p>
          )}

          {result.verdict === "phishing" && <RemediationTips tips={EMAIL_REMEDIATION_TIPS} />}

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
