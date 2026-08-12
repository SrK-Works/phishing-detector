import { useEffect, useState } from "react";
import { fetchStats } from "../lib/api";
import type { StatsResponse } from "../types";

const COPY: Record<"url" | "email" | "phone", { safe: string; phishing: string }> = {
  url: { safe: "sites checked safe", phishing: "flagged as phishing" },
  email: { safe: "email domains checked safe", phishing: "flagged as suspicious" },
  phone: { safe: "phone numbers checked clean", phishing: "flagged as suspicious" },
};

// Three separate, tab-scoped counters rather than one combined total -- a
// URL/email/phone "phishing" verdict means three different things, and
// collapsing them into one number would hide that difference.
//
// `refreshToken` is bumped by the parent shell after each completed check
// so the count updates immediately rather than only on tab switch/mount.
export default function StatsFooter({
  type,
  refreshToken,
}: {
  type: "url" | "email" | "phone";
  refreshToken: number;
}) {
  const [stats, setStats] = useState<StatsResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchStats(type)
      .then((s) => !cancelled && setStats(s))
      .catch(() => !cancelled && setStats(null));
    return () => {
      cancelled = true;
    };
  }, [type, refreshToken]);

  const copy = COPY[type];
  return (
    <div className="mt-8 text-center">
      {stats && (
        <p className="text-xs text-gray-500">
          {stats.safe_count} {copy.safe} &middot; {stats.phishing_count} {copy.phishing}
        </p>
      )}
      <p className="mt-1 text-[11px] text-gray-600">
        What you check here is stored for 30 days (to avoid re-checking the
        same thing repeatedly), then deleted automatically.
      </p>
    </div>
  );
}
