import type { CheckResponse, EmailCheckResponse, PhoneCheckResponse, StatsResponse } from "../types";

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errorBody = await res.json().catch(() => null);
    throw new Error(errorBody?.detail ?? `Request failed (${res.status})`);
  }
  return res.json();
}

export function checkUrl(url: string): Promise<CheckResponse> {
  return postJson<CheckResponse>("/api/check", { url });
}

export function checkEmail(email: string): Promise<EmailCheckResponse> {
  return postJson<EmailCheckResponse>("/api/check-email", { email });
}

export function checkPhone(phone: string, region: string): Promise<PhoneCheckResponse> {
  return postJson<PhoneCheckResponse>("/api/check-phone", { phone, region });
}

export async function fetchStats(type: "url" | "email" | "phone" = "url"): Promise<StatsResponse> {
  const res = await fetch(`/api/stats?type=${type}`);
  if (!res.ok) throw new Error("Failed to load stats");
  return res.json();
}
