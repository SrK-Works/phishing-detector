import { useEffect, useState } from "react";
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

function VerdictBadge({
  verdict,
  lowConfidence,
}: {
  verdict: CheckResponse["verdict"];
  lowConfidence: boolean;
}) {
  const isSafe = verdict === "safe";
  if (lowConfidence) {
    return (
      <span className="inline-flex items-center rounded-full px-4 py-1.5 text-sm font-semibold bg-amber-500/15 text-amber-400">
        Uncertain
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center rounded-full px-4 py-1.5 text-sm font-semibold ${
        isSafe ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
      }`}
    >
      {isSafe ? "Looks legitimate" : "Likely phishing"}
    </span>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  return (
    <div className="mt-3">
      <div className="flex justify-between text-xs text-gray-400 mb-1">
        <span>Confidence</span>
        <span>{pct}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-gray-700">
        <div
          className="h-2 rounded-full bg-indigo-500 transition-all"
          style={{ width: `${pct}%` }}
        />
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

  const onSubmit = async (e: React.FormEvent) => {
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
          Paste a URL to check whether it looks legitimate or like a phishing site.
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
            className="rounded-lg bg-indigo-600 px-5 py-2.5 font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {loading ? "Checking..." : "Check"}
          </button>
        </form>

        {error && (
          <p className="mt-4 text-sm text-red-400 text-center">{error}</p>
        )}

        {result && (
          <div className="mt-6 rounded-xl border border-gray-700 bg-gray-800/50 p-5">
            {result.typosquat_target && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                As per the URL you entered, you might be looking for{" "}
                <strong>{result.typosquat_target}.com</strong> -- but this domain is a
                close lookalike, not the real thing.
              </div>
            )}
            {result.override_reason === "confirmed_threat" && (
              <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                Confirmed malicious by Google Safe Browsing's threat list.
              </div>
            )}
            {result.override_reason === "popular_domain" && (
              <div className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
                This domain ranks #{result.popularity_rank?.toLocaleString()} among the
                world's most-visited sites, which outweighs an otherwise shaky
                signal from our own checks.
              </div>
            )}
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <span className="text-sm text-gray-400 break-all">{result.url}</span>
              <VerdictBadge verdict={result.verdict} lowConfidence={result.low_confidence} />
            </div>
            <ConfidenceBar confidence={result.confidence} />

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

            {result.reasons.length > 0 && (
              <div className="mt-5">
                <p className="text-xs uppercase tracking-wide text-gray-500 mb-2">
                  Why
                </p>
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
