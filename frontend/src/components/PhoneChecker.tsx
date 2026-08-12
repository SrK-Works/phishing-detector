import { useState, type FormEvent } from "react";
import { checkPhone } from "../lib/api";
import type { PhoneCheckResponse } from "../types";
import {
  ConfidenceGauge,
  HowItWorks,
  RemediationTips,
  ResultSkeleton,
  ShieldIcon,
  TONE_BORDER_CLASS,
  TONE_TEXT_CLASS,
  verdictLabel,
  verdictTone,
} from "./shared";

const PHONE_REMEDIATION_TIPS = [
  "Don't call this number back, especially if it's premium-rate.",
  "Never share an OTP, PIN, or personal details on a call you didn't initiate.",
  "If you weren't expecting contact from this organization, reach them through a number/channel you already know to be real.",
];

const LABELS = { safe: "No issues found", phishing: "Flagged" };

// A handful of common regions -- not exhaustive, just enough to cover the
// likely audience without adding a library for a plain <select>.
const REGIONS = [
  { code: "IN", label: "India (+91)" },
  { code: "US", label: "United States (+1)" },
  { code: "GB", label: "United Kingdom (+44)" },
  { code: "AU", label: "Australia (+61)" },
  { code: "AE", label: "UAE (+971)" },
  { code: "SG", label: "Singapore (+65)" },
];

const LINE_TYPE_LABELS: Record<string, string> = {
  MOBILE: "Mobile",
  FIXED_LINE: "Landline",
  FIXED_LINE_OR_MOBILE: "Mobile or landline",
  TOLL_FREE: "Toll-free",
  PREMIUM_RATE: "Premium-rate",
  SHARED_COST: "Shared-cost",
  VOIP: "VOIP",
  PERSONAL_NUMBER: "Personal number",
  PAGER: "Pager",
  UAN: "Universal access number",
  VOICEMAIL: "Voicemail",
  UNKNOWN: "Unknown",
};

export default function PhoneChecker({ onChecked }: { onChecked?: () => void }) {
  const [phone, setPhone] = useState("");
  const [region, setRegion] = useState("IN");
  const [result, setResult] = useState<PhoneCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!phone.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await checkPhone(phone.trim(), region);
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
      <h1 className="text-3xl font-bold text-center text-gray-100">Phone Number Checker</h1>
      <p className="text-center text-gray-400 mt-2 text-sm">
        Validates a number's format and identifies its line type and
        carrier.
      </p>
      <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-300 text-center">
        Lighter check than the other two -- unlike a domain, a phone number
        has no public "who owns this" registry. This validates format and
        line type only; it can't confirm who a number actually belongs to.
      </div>
      <HowItWorks>
        <p>
          Enter any phone number. Unlike a website or email domain, there's
          no public record of which company owns a phone number -- so this
          check is intentionally lighter than the other two, and won't tell
          you "this is/isn't really Company X's number."
        </p>
        <p>
          What it can tell you: whether the number is validly formatted,
          what type of line it is (mobile, landline, toll-free, VOIP), and
          which carrier issued it. It'll flag obviously invalid numbers and
          premium-rate numbers -- calling one back can rack up charges, a
          common scam pattern -- but everything else is shown as
          information, not a verdict.
        </p>
      </HowItWorks>

      <form onSubmit={onSubmit} className="mt-6 flex flex-col sm:flex-row gap-2">
        <select
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          className="rounded-lg bg-gray-800 border border-gray-700 px-3 py-2.5 text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          {REGIONS.map((r) => (
            <option key={r.code} value={r.code}>
              {r.label}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          placeholder="98765 43210 or +91 98765 43210"
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
          <div className="flex items-center gap-4">
            <ConfidenceGauge confidence={result.confidence} tone={verdictTone(result)} />
            <div className="min-w-0">
              <div className={`flex items-center gap-1.5 font-semibold ${TONE_TEXT_CLASS[verdictTone(result)]}`}>
                <ShieldIcon tone={verdictTone(result)} />
                {verdictLabel(result, LABELS)}
              </div>
              <p className="text-xs text-gray-500 mt-0.5">{result.e164 ?? "Could not be parsed"}</p>
            </div>
          </div>

          <div className="mt-5">
            <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">Details</p>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5 text-sm text-gray-300">
              <li>
                <span className="text-gray-500">Valid format: </span>
                {result.is_valid ? "Yes" : result.is_possible ? "Plausible length, but not valid" : "No"}
              </li>
              <li>
                <span className="text-gray-500">Region: </span>
                {result.region_code ?? "Unknown"}
              </li>
              <li>
                <span className="text-gray-500">Line type: </span>
                {result.line_type ? (LINE_TYPE_LABELS[result.line_type] ?? result.line_type) : "Unknown"}
              </li>
              <li>
                <span className="text-gray-500">Carrier: </span>
                {result.carrier_name || "Coverage unavailable for this number"}
              </li>
            </ul>
            {result.line_type === "VOIP" && (
              <p className="mt-2 text-xs text-gray-500">
                This is a VOIP number -- common for legitimate businesses too,
                shown for information only, not scored as a red flag.
              </p>
            )}
          </div>

          {result.override_reason === "unparseable_number" && (
            <p className="mt-3 text-xs text-amber-400">
              This doesn't look like a phone number at all.
            </p>
          )}
          {result.override_reason === "invalid_format" && (
            <p className="mt-3 text-xs text-amber-400">
              This doesn't match a valid number format for its region.
            </p>
          )}
          {result.override_reason === "premium_rate_number" && (
            <>
              <p className="mt-3 text-xs text-amber-400">
                This is a premium-rate number -- calling it can incur charges,
                a pattern common in scam call-back schemes.
              </p>
              <RemediationTips tips={PHONE_REMEDIATION_TIPS} />
            </>
          )}
        </div>
      )}
    </>
  );
}
