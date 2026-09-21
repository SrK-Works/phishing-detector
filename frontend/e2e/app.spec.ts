import { expect, test } from "@playwright/test";

test("flags a domain that cannot be resolved as phishing with an explanation", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("textbox", { name: /example\.com/i }).fill("http://secure-appleid-verify.tk/login");
  await page.getByRole("button", { name: "Check" }).click();

  await expect(page.getByText(/Uncertain|Likely phishing/i).first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("Signals checked")).toBeVisible();
  await expect(page.getByText("Domain resolves:")).toBeVisible();
  await expect(page.getByText("What to do now")).toBeVisible();
});

test("checks a well-known domain as safe", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("textbox", { name: /example\.com/i }).fill("https://www.google.com");
  await page.getByRole("button", { name: "Check" }).click();

  await expect(page.getByText("Looks legitimate").first()).toBeVisible({ timeout: 20_000 });
});

test("switches between URL, Email, and Phone checkers", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "URL Safety Checker" })).toBeVisible();

  await page.getByRole("button", { name: "Email" }).click();
  await expect(page.getByRole("heading", { name: "Email Domain Checker" })).toBeVisible();

  await page.getByRole("button", { name: "Phone" }).click();
  await expect(page.getByRole("heading", { name: /Phone/i })).toBeVisible();
});
