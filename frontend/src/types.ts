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
  typosquat_real_domain: string | null;
  typosquat_diff: string | null;
  popularity_rank: number | null;
  override_reason:
    | "confirmed_threat"
    | "virustotal_flagged"
    | "typosquat_lookalike"
    | "domain_unreachable"
    | "popular_domain"
    | "no_track_record"
    | null;
  reasons: Reason[];
  site_description: string | null;
  reason_narrative: string | null;
  domain_age_days: number | null;
  tls_cert_age_days: number | null;
  dns_resolves: boolean | null;
  redirect_count: number;
  safe_browsing_available: boolean;
  safe_browsing_checked: boolean;
  virustotal_available: boolean;
  virustotal_checked: boolean;
  virustotal_malicious_count: number | null;
  virustotal_total_engines: number | null;
  partial: boolean;
  cached: boolean;
}

export interface StatsResponse {
  safe_count: number;
  phishing_count: number;
}
