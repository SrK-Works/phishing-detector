import { afterEach, describe, expect, it, vi } from "vitest";
import { checkEmail, checkPhone, checkUrl, fetchStats } from "./api";

function mockFetchOnce(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkUrl", () => {
  it("posts to /api/check with the url and returns the parsed body", async () => {
    mockFetchOnce(200, { verdict: "safe", confidence: 0.9 });
    const result = await checkUrl("https://example.com");
    expect(fetch).toHaveBeenCalledWith(
      "/api/check",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ url: "https://example.com" }),
      }),
    );
    expect(result).toEqual({ verdict: "safe", confidence: 0.9 });
  });

  it("throws the backend's detail message on a non-2xx response", async () => {
    mockFetchOnce(422, { detail: "That doesn't look like a URL." });
    await expect(checkUrl("not a url")).rejects.toThrow("That doesn't look like a URL.");
  });

  it("falls back to a generic message when the error body isn't JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.reject(new Error("not json")),
      }),
    );
    await expect(checkUrl("https://example.com")).rejects.toThrow("Request failed (500)");
  });
});

describe("checkEmail", () => {
  it("posts to /api/check-email with the email", async () => {
    mockFetchOnce(200, { verdict: "safe" });
    await checkEmail("user@example.com");
    expect(fetch).toHaveBeenCalledWith(
      "/api/check-email",
      expect.objectContaining({ body: JSON.stringify({ email: "user@example.com" }) }),
    );
  });
});

describe("checkPhone", () => {
  it("posts to /api/check-phone with the phone and region", async () => {
    mockFetchOnce(200, { verdict: "safe" });
    await checkPhone("9876543210", "IN");
    expect(fetch).toHaveBeenCalledWith(
      "/api/check-phone",
      expect.objectContaining({ body: JSON.stringify({ phone: "9876543210", region: "IN" }) }),
    );
  });
});

describe("fetchStats", () => {
  it("defaults to type=url", async () => {
    mockFetchOnce(200, { safe_count: 1, phishing_count: 2 });
    await fetchStats();
    expect(fetch).toHaveBeenCalledWith("/api/stats?type=url");
  });

  it("passes through the requested type", async () => {
    mockFetchOnce(200, { safe_count: 1, phishing_count: 2 });
    await fetchStats("phone");
    expect(fetch).toHaveBeenCalledWith("/api/stats?type=phone");
  });

  it("throws a generic message on failure", async () => {
    mockFetchOnce(500, {});
    await expect(fetchStats("email")).rejects.toThrow("Failed to load stats");
  });
});
