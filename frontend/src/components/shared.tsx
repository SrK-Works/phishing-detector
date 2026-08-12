// Visual primitives shared by all three checker tabs (URL/Email/Phone) --
// each tab's own verdict/response shape differs, so these only depend on
// the minimal fields every checker's response has in common (VerdictLike),
// plus optional label overrides so each tab can supply its own wording
// while reusing the same gauge/icon/skeleton.

import { useState, type ReactNode } from "react";

export type Tone = "safe" | "phishing" | "uncertain";

export interface VerdictLike {
  verdict: "safe" | "phishing";
  confidence: number;
  low_confidence: boolean;
}

export interface VerdictLabels {
  safe: string;
  phishing: string;
}

const DEFAULT_LABELS: VerdictLabels = {
  safe: "Looks legitimate",
  phishing: "Likely phishing",
};

export const TONE_HEX: Record<Tone, string> = {
  safe: "#34d399",
  phishing: "#f87171",
  uncertain: "#fbbf24",
};

export const TONE_TEXT_CLASS: Record<Tone, string> = {
  safe: "text-emerald-400",
  phishing: "text-red-400",
  uncertain: "text-amber-400",
};

export const TONE_BORDER_CLASS: Record<Tone, string> = {
  safe: "border-l-emerald-500",
  phishing: "border-l-red-500",
  uncertain: "border-l-amber-500",
};

export function verdictTone(result: VerdictLike): Tone {
  if (result.low_confidence) return "uncertain";
  return result.verdict === "safe" ? "safe" : "phishing";
}

export function verdictLabel(result: VerdictLike, labels: VerdictLabels = DEFAULT_LABELS): string {
  if (result.low_confidence) return "Uncertain";
  return result.verdict === "safe" ? labels.safe : labels.phishing;
}

// One shield glyph whose shape changes with the verdict, colored via
// currentColor so it always matches the surrounding tone class.
export function ShieldIcon({ tone }: { tone: Tone }) {
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
export function ConfidenceGauge({ confidence, tone }: { confidence: number; tone: Tone }) {
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

export function formatAge(days: number): string {
  if (days >= 365) {
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? "" : "s"} old`;
  }
  return `${days} day${days === 1 ? "" : "s"} old`;
}

export interface SignalRow {
  label: string;
  value: string;
  known: boolean;
}

export function SignalList({ signals }: { signals: SignalRow[] }) {
  return (
    <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
      {signals.map((s) => (
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
  );
}

export function ResultSkeleton() {
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

// Collapsed by default so the primary "paste something and check it" flow
// stays uncluttered -- the explanation is there for whoever wants it,
// without pushing the input field down the page for everyone else.
function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`h-3.5 w-3.5 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

export function HowItWorks({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-4 text-center">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 text-xs font-medium text-indigo-400 hover:text-indigo-300"
      >
        How this works
        <ChevronIcon open={open} />
      </button>
      {open && (
        <div className="mt-3 rounded-lg border border-gray-700 bg-gray-800/40 p-4 text-sm text-gray-300 leading-relaxed text-left space-y-3">
          {children}
        </div>
      )}
    </div>
  );
}

// A verdict alone isn't much use in the moment someone's actually worried
// about a specific message/link/number -- this is the actionable follow-up,
// shown only on a "phishing" call (not "uncertain"/"safe"), so it never
// competes with the main signals for attention when there's nothing to act on.
export function RemediationTips({ tips }: { tips: string[] }) {
  return (
    <div className="mt-5 rounded-lg border border-red-500/30 bg-red-500/5 p-4">
      <p className="text-xs uppercase tracking-wide text-red-300 mb-2">What to do now</p>
      <ul className="space-y-1.5">
        {tips.map((tip) => (
          <li key={tip} className="text-sm text-gray-300 flex items-start gap-2">
            <span className="mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 bg-red-400" />
            {tip}
          </li>
        ))}
      </ul>
    </div>
  );
}
