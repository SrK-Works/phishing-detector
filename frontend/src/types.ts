export interface Reason {
  feature: string;
  impact: number;
}

export interface CheckResponse {
  url: string;
  verdict: "safe" | "phishing";
  confidence: number;
  reasons: Reason[];
  partial: boolean;
  cached: boolean;
}

export interface StatsResponse {
  safe_count: number;
  phishing_count: number;
}
