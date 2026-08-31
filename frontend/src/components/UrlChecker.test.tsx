import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import UrlChecker from "./UrlChecker";
import { checkUrl } from "../lib/api";
import type { CheckResponse } from "../types";

vi.mock("../lib/api", () => ({
  checkUrl: vi.fn(),
}));

const BASE_RESULT: CheckResponse = {
  url: "https://example.com",
  verdict: "safe",
  confidence: 0.92,
  low_confidence: false,
  missing_signals: [],
  is_exact_brand_domain: false,
  known_brand_display_name: null,
  typosquat_target: null,
  typosquat_brand_display: null,
  typosquat_real_domain: null,
  typosquat_diff: null,
  popularity_rank: 100,
  override_reason: null,
  reasons: [],
  site_description: null,
  reason_narrative: null,
  domain_age_days: 900,
  tls_cert_age_days: 30,
  dns_resolves: true,
  redirect_count: 0,
  safe_browsing_available: false,
  safe_browsing_checked: false,
  virustotal_available: false,
  virustotal_checked: false,
  virustotal_malicious_count: null,
  virustotal_total_engines: null,
  partial: false,
  cached: false,
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("UrlChecker", () => {
  it("does not call checkUrl when the input is empty", async () => {
    const user = userEvent.setup();
    render(<UrlChecker />);
    await user.click(screen.getByRole("button", { name: /check/i }));
    expect(checkUrl).not.toHaveBeenCalled();
  });

  it("submits the trimmed url and renders the verdict on success", async () => {
    vi.mocked(checkUrl).mockResolvedValue(BASE_RESULT);
    const onChecked = vi.fn();
    const user = userEvent.setup();
    render(<UrlChecker onChecked={onChecked} />);

    await user.type(screen.getByPlaceholderText(/example.com/i), "  https://example.com  ");
    await user.click(screen.getByRole("button", { name: /check/i }));

    expect(checkUrl).toHaveBeenCalledWith("https://example.com");
    await waitFor(() => expect(screen.getByText("Looks legitimate")).toBeInTheDocument());
    expect(onChecked).toHaveBeenCalledOnce();
  });

  it("shows the API's error message when the check fails", async () => {
    vi.mocked(checkUrl).mockRejectedValue(new Error("That doesn't look like a URL."));
    const user = userEvent.setup();
    render(<UrlChecker />);

    await user.type(screen.getByPlaceholderText(/example.com/i), "not-a-url");
    await user.click(screen.getByRole("button", { name: /check/i }));

    await waitFor(() =>
      expect(screen.getByText("That doesn't look like a URL.")).toBeInTheDocument(),
    );
  });

  it("shows the typosquat banner when the result flags a lookalike domain", async () => {
    vi.mocked(checkUrl).mockResolvedValue({
      ...BASE_RESULT,
      verdict: "phishing",
      typosquat_target: "paypal",
      typosquat_real_domain: "paypal.com",
    });
    const user = userEvent.setup();
    render(<UrlChecker />);

    await user.type(screen.getByPlaceholderText(/example.com/i), "paypa1.com");
    await user.click(screen.getByRole("button", { name: /check/i }));

    await waitFor(() => expect(screen.getByText(/mimicking/i)).toBeInTheDocument());
    expect(screen.getByText("paypal.com")).toBeInTheDocument();
  });
});
