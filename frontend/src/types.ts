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
  is_exact_brand_domain: boolean;
  known_brand_display_name: string | null;
  typosquat_target: string | null;
  typosquat_brand_display: string | null;
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

export interface EmailCheckResponse {
  domain: string;
  verdict: "safe" | "phishing";
  confidence: number;
  low_confidence: boolean;
  score: number;
  override_reason:
    | "known_brand_domain"
    | "confirmed_threat"
    | "virustotal_flagged"
    | "typosquat_lookalike"
    | null;
  is_exact_brand_domain: boolean;
  known_brand_display_name: string | null;
  typosquat_target: string | null;
  typosquat_brand_display: string | null;
  typosquat_real_domain: string | null;
  typosquat_diff: string | null;
  popularity_rank: number | null;
  dns_resolves: boolean | null;
  mx_present: boolean | null;
  spf_present: boolean | null;
  dmarc_present: boolean | null;
  domain_age_days: number | null;
  has_valid_https: boolean | null;
  safe_browsing_available: boolean;
  safe_browsing_checked: boolean;
  virustotal_available: boolean;
  virustotal_checked: boolean;
  virustotal_malicious_count: number | null;
  virustotal_total_engines: number | null;
  cached: boolean;
}

export interface PhoneCheckResponse {
  e164: string | null;
  region_code: string | null;
  is_valid: boolean;
  is_possible: boolean;
  line_type: string | null;
  carrier_name: string | null;
  verdict: "safe" | "phishing";
  confidence: number;
  low_confidence: boolean;
  override_reason: "unparseable_number" | "invalid_format" | "premium_rate_number" | null;
}
