import { expect, test } from "@playwright/test";
test("sample timeline, comparison and report contain useful evidence", async ({
  page,
}) => {
  await page.goto("./");
  await page.getByRole("button", { name: /delivery-7b/ }).click();
  await expect(
    page.getByText("Response reached the sender’s time limit", { exact: true }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await page.getByLabel("Second attempt").selectOption("2");
  await expect(page.getByText("120 seconds", { exact: true })).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export report" }).click(),
  ]);
  expect(download.suggestedFilename()).toBe("payload-clinic-report.md");
  const stream = await download.createReadStream();
  let text = "";
  for await (const chunk of stream!) text += chunk;
  expect(text).toContain("Sender time limit: 3000 ms");
  expect(text).not.toContain("marisol@example.test");
  expect(text).not.toContain("synthetic-private-value");
});
test("invalid input stays open with an actionable error and valid import is redacted before storage", async ({
  page,
}) => {
  await page.goto("./");
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await page.getByLabel("Or paste an incident").fill("{");
  await page.getByRole("button", { name: "Validate and import" }).click();
  await expect(page.getByRole("alert")).toContainText("not valid JSON");
  await page
    .getByLabel("Or paste an incident")
    .fill(
      JSON.stringify({
        title: "Imported incident",
        senderTimeoutMs: 2000,
        attempts: [
          {
            id: "attempt-48",
            eventId: "evt-48",
            receivedAt: "2026-10-18T14:00:00Z",
            status: 422,
            durationMs: 90,
            headers: { Authorization: "Bearer topsecret-48" },
            requestBody:
              '{"email":"sample@example.test","secret":"topsecret-48"}',
            responseBody: "topsecret-48",
          },
        ],
      }),
    );
  await page.getByRole("button", { name: "Validate and import" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Imported incident" }),
  ).toBeVisible();
  const saved = await page.evaluate(() => JSON.stringify(localStorage));
  expect(saved).not.toContain("topsecret-48");
  expect(saved).not.toContain("sample@example.test");
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Imported incident" }),
  ).toBeVisible();
});
test("signature inputs remain transient and reformatting invalidates the digest", async ({
  page,
}) => {
  await page.goto("./");
  await page.getByRole("tab", { name: "Signature check" }).click();
  await page
    .getByRole("button", { name: "Load signed sample", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Signature matches", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Reformat JSON to compare" }).click();
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Signature does not match",
      exact: true,
    }),
  ).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(
    "synthetic-demo-key-not-a-live-secret",
  );
  await page.getByRole("tab", { name: "Delivery evidence" }).click();
  await page.getByRole("tab", { name: "Signature check" }).click();
  await expect(page.getByLabel(/^Signing secret/)).toHaveValue("");
});
test("mobile timeline and import remain usable without a page-wide horizontal scroll", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./");
  await expect(
    page.getByRole("heading", { name: "Follow the delivery." }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
});

test("import dialog traps keyboard focus, closes on Escape and restores the trigger", async ({
  page,
}) => {
  await page.goto("./");
  const trigger = page.getByRole("button", {
    name: "Import incident",
    exact: true,
  });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("button", { name: "Close", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(
    page.getByRole("button", { name: "Download sample format", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Close", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(trigger).toBeFocused();
});
