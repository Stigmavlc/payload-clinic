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
  await expect(page.getByText("2 minutes", { exact: true })).toBeVisible();
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
  await page.getByLabel("Or paste an incident").fill(
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
          requestBody: JSON.stringify({
            email: "sample@example.test",
            secret: "topsecret-48",
            results: {
              "jane@example.test": { status: "delivered" },
              "joe@example.test": { status: "bounced", reason: "mailbox full" },
            },
          }),
          responseBody: "topsecret-48",
        },
        {
          id: "attempt-49",
          eventId: "evt-48",
          receivedAt: "2026-10-18T14:01:00Z",
          status: 200,
          durationMs: 80,
          headers: {},
          requestBody:
            "token=second-secret-49&quantity=3&note=second-secret-49",
          responseBody: '{"password":"third-secret-49","amount":10.50}',
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
  expect(saved).not.toContain("second-secret-49");
  expect(saved).not.toContain("third-secret-49");
  await page.getByText("Headers and redaction log").click();
  const originalSaved = await page.evaluate(() =>
    localStorage.getItem("payload-clinic.incident.v1"),
  );
  expect(originalSaved).toContain("mailbox full");
  const originalLog = await page
    .locator(".redaction-list li")
    .allTextContents();
  expect(originalLog.length).toBeGreaterThan(2);
  await page.reload();
  expect(
    await page.evaluate(() =>
      localStorage.getItem("payload-clinic.incident.v1"),
    ),
  ).toBe(originalSaved);
  await page.getByText("Headers and redaction log").click();
  expect(await page.locator(".redaction-list li").allTextContents()).toEqual(
    originalLog,
  );
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
    page.getByRole("heading", { name: "Delivery timeline" }),
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

test("expired signatures show a rejected timestamp before the matching digest", async ({
  page,
}) => {
  await page.goto("./");
  await page.getByRole("tab", { name: "Signature check" }).click();
  await page
    .getByRole("button", { name: "Load expired sample", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Timestamp outside tolerance",
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.locator(".result")).toHaveClass(/error/);
  await expect(page.locator(".result")).toContainText(/seconds ago/);
  await expect(page.locator(".result")).toContainText(
    "Digest comparison: matches",
  );
});

test("capture the three documented views at desktop width", async ({
  page,
}) => {
  test.skip(
    !process.env.CAPTURE_DOCS,
    "Documentation capture is requested separately.",
  );
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("./");
  await page.getByRole("button", { name: /delivery-7b/ }).click();
  await page
    .getByRole("heading", { name: "Delivery timeline", exact: true })
    .click();
  await page.mouse.move(0, 0);
  await page.screenshot({
    path: "docs/screenshots/evidence.png",
    fullPage: true,
  });
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await page.getByLabel("Second attempt").selectOption("2");
  await page.mouse.move(0, 0);
  await page.screenshot({
    path: "docs/screenshots/comparison.png",
    fullPage: true,
  });
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
  await page.mouse.move(0, 0);
  await page.screenshot({
    path: "docs/screenshots/signature.png",
    fullPage: true,
  });
});

test("a redacted title survives reload and an unreadable saved copy is preserved", async ({
  page,
}) => {
  await page.goto("./");
  const title = "a@b.co c@d.co " + "x".repeat(166);
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title,
      senderTimeoutMs: 1000,
      attempts: [
        {
          id: "first",
          eventId: "event",
          receivedAt: "2026-10-19T10:00:00Z",
          status: 200,
          durationMs: 20,
          headers: {},
          requestBody: "{}",
          responseBody: "",
        },
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  const heading = await page.locator(".main-heading h2").innerText();
  expect(heading.length).toBeGreaterThan(180);
  await page.reload();
  await expect(page.locator(".main-heading h2")).toHaveText(heading);
  await page.evaluate(() =>
    localStorage.setItem("payload-clinic.incident.v1", "{unreadable"),
  );
  await page.reload();
  await expect(
    page.getByText(/saved incident could not be reopened/),
  ).toBeVisible();
  expect(
    await page.evaluate(() =>
      localStorage.getItem("payload-clinic.incident.v1"),
    ),
  ).toBe("{unreadable");
});

test("multi-day attempts show dates and readable retry gaps", async ({
  page,
}) => {
  await page.goto("./");
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  const attempt = {
    id: "early",
    eventId: "same",
    receivedAt: "2026-10-17T10:00:00Z",
    status: 503,
    durationMs: 20,
    headers: {},
    requestBody: "{}",
    responseBody: "",
  };
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title: "Two-day retries",
      senderTimeoutMs: 1000,
      attempts: [
        attempt,
        { ...attempt, id: "late", receivedAt: "2026-10-18T10:00:01Z" },
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  await expect(page.locator(".timeline")).toContainText(
    "2026-10-17 10:00:00 UTC",
  );
  await expect(page.locator(".timeline")).toContainText(
    "2026-10-18 10:00:01 UTC",
  );
  await expect(page.locator(".timeline")).toContainText(
    "1 day, 1 second after previous attempt",
  );
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await expect(
    page.getByText("1 day, 1 second", { exact: true }),
  ).toBeVisible();
});

for (const width of [1440, 390]) {
  test(`import and log spacing remains readable at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto("./");
    await page
      .getByRole("button", { name: "Import incident", exact: true })
      .click();
    expect(
      await page
        .locator(".import-dialog p.muted")
        .evaluate((e) => parseFloat(getComputedStyle(e).marginBottom)),
    ).toBeGreaterThan(12);
    await page.getByLabel("Or paste an incident").fill("{");
    await page.getByRole("button", { name: "Validate and import" }).click();
    expect(
      await page
        .getByRole("alert")
        .evaluate((e) => parseFloat(getComputedStyle(e).marginTop)),
    ).toBeGreaterThan(4);
    await page.screenshot({
      path: `test-results/import-${width}.png`,
      fullPage: true,
    });
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await page.getByText("Headers and redaction log").click();
    const heading = page.getByRole("heading", {
      name: "Selected headers",
      exact: true,
    });
    expect(
      await heading.evaluate((e) => parseFloat(getComputedStyle(e).marginTop)),
    ).toBeGreaterThan(12);
    await heading.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: `test-results/log-${width}.png`,
      fullPage: true,
    });
  });
}

test("imported records keep their identity and export has a visible mobile label", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./");
  await expect(
    page.getByText("Fictional delivery records, safe to explore.", {
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title: "Slow response and retries",
      example: "booking",
      senderTimeoutMs: 1000,
      attempts: [
        {
          id: "private-input",
          eventId: "event",
          receivedAt: "2026-10-19T10:00:00Z",
          status: 200,
          durationMs: 20,
          headers: {},
          requestBody: "{}",
          responseBody: "{}",
        },
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  await expect(
    page.getByText("Fictional delivery records, safe to explore.", {
      exact: true,
    }),
  ).not.toBeVisible();
  await expect(page.getByLabel("Synthetic examples")).toHaveValue("custom");
  await page.reload();
  await expect(page.getByLabel("Synthetic examples")).toHaveValue("custom");
  const exportButton = page.getByRole("button", {
    name: "Export report",
    exact: true,
  });
  await expect(exportButton).toBeVisible();
  expect(
    await exportButton.evaluate((e) =>
      parseFloat(getComputedStyle(e).fontSize),
    ),
  ).toBeGreaterThan(10);
  expect(
    await page.locator(".payload-grid .eyebrow").allTextContents(),
  ).toEqual(["Redacted", "Redacted"]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});
