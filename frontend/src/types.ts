export interface Reason {
  feature: string;
  impact: number;
}

export interface CheckResponse {
  url: string;
  verdict: "safe" | "phishing";
  confidence: number;
  low_confidence: boolean;
  missing_signals: string[];
  typosquat_target: string | null;
  popularity_rank: number | null;
  override_reason:
    | "confirmed_threat"
    | "typosquat_lookalike"
    | "popular_domain"
    | "no_track_record"
    | null;
  reasons: Reason[];
  partial: boolean;
  cached: boolean;
}

export interface StatsResponse {
  safe_count: number;
  phishing_count: number;
}
