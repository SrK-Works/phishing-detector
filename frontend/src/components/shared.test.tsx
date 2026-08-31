import { describe, expect, it } from "vitest";
import { formatAge, verdictLabel, verdictTone } from "./shared";

describe("verdictTone", () => {
  it("returns 'uncertain' when low_confidence is set, regardless of verdict", () => {
    expect(verdictTone({ verdict: "safe", confidence: 0.5, low_confidence: true })).toBe("uncertain");
    expect(verdictTone({ verdict: "phishing", confidence: 0.5, low_confidence: true })).toBe("uncertain");
  });

  it("maps safe/phishing verdicts directly when confidence is high", () => {
    expect(verdictTone({ verdict: "safe", confidence: 0.95, low_confidence: false })).toBe("safe");
    expect(verdictTone({ verdict: "phishing", confidence: 0.95, low_confidence: false })).toBe("phishing");
  });
});

describe("verdictLabel", () => {
  it("returns 'Uncertain' for low-confidence results", () => {
    expect(verdictLabel({ verdict: "safe", confidence: 0.5, low_confidence: true })).toBe("Uncertain");
  });

  it("uses the default labels when none are supplied", () => {
    expect(verdictLabel({ verdict: "safe", confidence: 0.9, low_confidence: false })).toBe("Looks legitimate");
    expect(verdictLabel({ verdict: "phishing", confidence: 0.9, low_confidence: false })).toBe("Likely phishing");
  });

  it("uses custom labels when supplied", () => {
    const labels = { safe: "Clean", phishing: "Suspicious" };
    expect(verdictLabel({ verdict: "safe", confidence: 0.9, low_confidence: false }, labels)).toBe("Clean");
    expect(verdictLabel({ verdict: "phishing", confidence: 0.9, low_confidence: false }, labels)).toBe(
      "Suspicious",
    );
  });
});

describe("formatAge", () => {
  it("formats sub-year ages in days, with correct singular/plural", () => {
    expect(formatAge(1)).toBe("1 day old");
    expect(formatAge(30)).toBe("30 days old");
  });

  it("formats year-or-older ages in years, with correct singular/plural", () => {
    expect(formatAge(365)).toBe("1 year old");
    expect(formatAge(800)).toBe("2 years old");
  });
});
