import { expect, test } from "@playwright/test";
test("sample timeline, comparison and report contain useful evidence", async ({
  page,
}) => {
  await page.goto("./");
  const iconUrl = await page
    .locator('link[rel="icon"]')
    .evaluate((node: HTMLLinkElement) => node.href);
  expect(new URL(iconUrl).pathname).toBe("/payload-clinic/favicon.svg");
  const icon = await page.request.get(iconUrl);
  expect(icon.headers()["content-type"]).toContain("image/svg+xml");
  expect(await icon.text()).toContain("<svg");
  await page.getByRole("button", { name: /delivery-7b/ }).click();
  await expect(
    page.getByText("Response reached the sender’s time limit", { exact: true }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await expect(page.getByLabel("Second attempt")).toHaveValue("2");
  await expect(
    page.getByLabel("Second attempt").locator('option[value="1"]'),
  ).toHaveAttribute("disabled", "");
  await expect(page.locator(".payload-grid h4")).toHaveText([
    "delivery-7b",
    "delivery-7c",
  ]);
  await expect(page.getByText("2 minutes", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /delivery-7c/ }).click();
  await expect(page.getByLabel("Second attempt")).not.toHaveValue("2");
  await expect(page.locator(".payload-grid h4").first()).toHaveText(
    "delivery-7c",
  );
  await expect(page.locator(".payload-grid h4").last()).not.toHaveText(
    "delivery-7c",
  );
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export report" }).click(),
  ]);
  expect(download.suggestedFilename()).toBe("payload-clinic-report.md");
  const stream = await download.createReadStream();
  let text = "";
  for await (const chunk of stream!) text += chunk;
  expect(text).toContain("Sender time limit: 3,000 ms");
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
            "verbose&token=second-secret-49&quantity=3&note=second-secret-49",
          responseBody:
            '{"password":"third-secret-49"},\n{"token":"fourth-secret-49"}',
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
  expect(saved).not.toContain("fourth-secret-49");
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
  await expect(
    page.getByRole("link", { name: "Stripe webhook signatures", exact: true }),
  ).toHaveCSS("text-decoration-line", "underline");
  await expect(
    page.getByRole("link", { name: "RFC 4231", exact: true }),
  ).toHaveCSS("text-decoration-line", "underline");
  await page.getByLabel("Raw request body").fill("{");
  await page.getByRole("button", { name: "Reformat JSON to compare" }).click();
  await expect(
    page.getByText(
      "The body cannot be reformatted because it is not valid JSON.",
    ),
  ).toBeVisible();
  await page.getByLabel("Raw request body").fill('{ "status": "ok" }');
  await expect(
    page.getByText(
      "The body cannot be reformatted because it is not valid JSON.",
    ),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Reformat JSON to compare" }).click();
  await expect(page.getByLabel("Raw request body")).toHaveValue(
    '{"status":"ok"}',
  );
  await expect(page.locator(".error")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await expect(
    page.getByText("Enter the signing secret for this session."),
  ).toBeVisible();
  await page.getByLabel(/^Signing secret/).fill("synthetic-revised-key-922");
  await expect(page.locator(".error")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await expect(
    page.getByText("The header needs exactly one integer t timestamp."),
  ).toBeVisible();
  await page.getByLabel("Stripe-Signature header").fill("t=1000");
  await expect(page.locator(".error")).toHaveCount(0);
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
  await expect(page.locator(".result")).toContainText(/15 minutes.*ago/);
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
  await page.getByLabel("Synthetic examples").selectOption("inventory");
  expect(
    await page.evaluate(() =>
      localStorage.getItem("payload-clinic.incident.v1"),
    ),
  ).toBe("{unreadable");
  await page
    .getByRole("button", { name: "Remove saved copy", exact: true })
    .click();
  await expect(page.getByText(/Saved copy removed/)).toBeVisible();
  expect(
    await page.evaluate(() =>
      localStorage.getItem("payload-clinic.incident.v1"),
    ),
  ).toBeNull();
  await page.getByLabel("Synthetic examples").selectOption("booking");
  await expect(
    page.getByText("Redacted incident saved on this browser.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/saved incident could not be reopened/),
  ).not.toBeVisible();
  const replacement = await page.evaluate(() =>
    localStorage.getItem("payload-clinic.incident.v1"),
  );
  expect(replacement).not.toBeNull();
  expect(replacement).not.toBe("{unreadable");
  await page
    .getByRole("button", { name: "Remove saved copy", exact: true })
    .click();
  expect(
    await page.evaluate(() =>
      localStorage.getItem("payload-clinic.incident.v1"),
    ),
  ).toBeNull();
  await expect(page.getByText(/Saved copy removed/)).toBeVisible();
});

test("blocked storage shows an unavailable warning on first visit", async ({
  page,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("Storage denied", "SecurityError");
      },
    });
  });
  await page.goto("./");
  await expect(
    page.getByText(
      "Browser storage is unavailable. Export the redacted report before closing.",
    ),
  ).toBeVisible();
  await expect(
    page.getByText(/saved incident could not be reopened/),
  ).not.toBeVisible();
});

test("English durations stay consistent when the browser uses Spanish", async ({
  browser,
  baseURL,
}) => {
  const context = await browser.newContext({ locale: "es-ES" });
  const page = await context.newPage();
  try {
    await page.goto(baseURL!);
    await page
      .getByRole("button", { name: "Import incident", exact: true })
      .click();
    const attempt = {
      id: "first",
      eventId: "same",
      receivedAt: "2026-10-19T10:00:00Z",
      status: 202,
      durationMs: 10450,
      headers: {},
      requestBody: "{}",
      responseBody: "",
    };
    await page.getByLabel("Or paste an incident").fill(
      JSON.stringify({
        title: "English duration format",
        senderTimeoutMs: 10000,
        attempts: [
          attempt,
          {
            ...attempt,
            id: "second",
            receivedAt: "2026-10-19T10:00:01.500Z",
          },
        ],
      }),
    );
    await page.getByRole("button", { name: "Validate and import" }).click();
    await expect(page.locator(".timeline")).toContainText("10,450 ms");
    await expect(page.locator(".timeline")).toContainText(
      "1.5 seconds after previous attempt",
    );
    await expect(page.locator(".reading")).toContainText(["202", "10,450 ms"]);
    await expect(page.locator(".findings")).toContainText(
      "10,450 ms was recorded against a 10,000 ms limit",
    );
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export report" }).click(),
    ]);
    const stream = await download.createReadStream();
    let output = "";
    for await (const chunk of stream!) output += chunk;
    expect(output).toContain("Sender time limit: 10,000 ms");
    expect(output).toContain("duration: 10,450 ms");
    expect(output).toContain("Gap from previous attempt: 1.5 seconds");
  } finally {
    await context.close();
  }
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
        {
          ...attempt,
          id: "late",
          receivedAt: "2026-10-18T10:00:01Z",
          status: null,
        },
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
  await expect(
    page.getByRole("button", { name: /Attempt 2: late/ }),
  ).toContainText("No response recorded");
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await expect(
    page
      .getByLabel("Second attempt")
      .getByRole("option", { name: "Attempt 2: late · No response recorded" }),
  ).toBeAttached();
  await expect(
    page.getByText("503 → No response recorded", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("1 day, 1 second", { exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 1000 });
  await page.getByRole("tab", { name: "Delivery evidence" }).click();
  await page.getByRole("button", { name: /Attempt 2: late/ }).click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/missing-response-390.png",
    fullPage: true,
  });
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

test("a single record explains that comparison needs another attempt", async ({
  page,
}) => {
  await page.goto("./");
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title: "Single attempt",
      senderTimeoutMs: 3000,
      attempts: [
        {
          id: "only-one",
          eventId: "evt-only",
          receivedAt: "2026-10-18T09:00:00Z",
          status: 200,
          durationMs: 100,
          headers: {},
          requestBody: "{}",
          responseBody: "",
        },
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  await page.getByRole("tab", { name: "Compare attempts" }).click();
  await expect(
    page.getByText(
      "A second attempt is needed to compare receiving-side records.",
    ),
  ).toBeVisible();
  await expect(page.getByLabel("Second attempt")).toHaveCount(0);
  await expect(page.locator(".comparison-summary")).toHaveCount(0);
});

test("a completed signature check cannot describe edited inputs", async ({
  page,
}) => {
  await page.goto("./");
  await page.getByRole("tab", { name: "Signature check" }).click();
  await page
    .getByRole("button", { name: "Load signed sample", exact: true })
    .click();
  await expect(page.getByLabel(/^Signing secret/)).not.toHaveValue("");
  await page.evaluate(() => {
    const sign = crypto.subtle.sign.bind(crypto.subtle);
    crypto.subtle.sign = async (...args: Parameters<typeof sign>) => {
      await new Promise<void>((resolve) => {
        (
          window as unknown as { releaseSignature: () => void }
        ).releaseSignature = resolve;
      });
      return sign(...args);
    };
  });
  await page
    .getByRole("button", { name: "Verify signature", exact: true })
    .click();
  await page.getByLabel(/^Signing secret/).fill("synthetic-changed-key-923");
  await page.evaluate(() =>
    (window as unknown as { releaseSignature: () => void }).releaseSignature(),
  );
  await expect(
    page.getByRole("button", { name: "Verify signature", exact: true }),
  ).toBeEnabled();
  await expect(page.locator(".result")).toHaveCount(0);
  await expect(page.locator(".error")).toHaveCount(0);
});

test("masking an undefined value preserves the invalid JSON observation after reload and export", async ({
  page,
}) => {
  await page.goto("./");
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title: "Broken value evidence",
      senderTimeoutMs: 2000,
      attempts: [
        {
          id: "invalid-953",
          eventId: "evt-953",
          receivedAt: "2026-10-18T14:00:00Z",
          status: 400,
          durationMs: 20,
          headers: {},
          requestBody: '{"amount":10,"token":undefined}',
          responseBody: '{"error":"invalid_json"}',
        },
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  const saved = await page.evaluate(() =>
    localStorage.getItem("payload-clinic.incident.v1"),
  );
  for (let i = 0; i < 3; i++) {
    await expect(
      page.getByText("Request body is not valid JSON", { exact: true }),
    ).toBeVisible();
    const body = JSON.parse(
      (await page.evaluate(() =>
        localStorage.getItem("payload-clinic.incident.v1"),
      ))!,
    ).attempts[0].requestBody;
    expect(body).toBe('{"amount":10,"token":[removed]}');
    expect(() => JSON.parse(body)).toThrow();
    expect(
      await page.evaluate(() =>
        localStorage.getItem("payload-clinic.incident.v1"),
      ),
    ).toBe(saved);
    if (i < 2) await page.reload();
  }
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export report" }).click(),
  ]);
  let output = "";
  for await (const chunk of (await download.createReadStream())!)
    output += chunk;
  expect(output).toContain('```text\n{"amount":10,"token":[removed]}');
  expect(output).toContain("Observed: Request body is not valid JSON");
  expect(output).not.toContain("undefined");
  await page.screenshot({
    path: test.info().outputPath("invalid-json-evidence.png"),
    fullPage: true,
  });
});

test("body check labels retain the original form and unsupported field scopes across reloads", async ({
  page,
}) => {
  await page.goto("./");
  await page
    .getByRole("button", { name: "Import incident", exact: true })
    .click();
  const plainBodies = [
    "{'password': 'synthetic-python-971'}",
    "{ password: 'synthetic-node-972' }",
  ];
  await page.getByLabel("Or paste an incident").fill(
    JSON.stringify({
      title: "Original check scopes",
      senderTimeoutMs: 2000,
      attempts: [
        {
          id: "scope-1",
          eventId: "evt-scope-1",
          receivedAt: "2026-10-18T14:00:00Z",
          status: 200,
          durationMs: 20,
          headers: {},
          requestBody: "jane%40example.test=delivered&token=synthetic-form-973",
          responseBody: "",
        },
        ...plainBodies.map((requestBody, index) => ({
          id: `scope-${index + 2}`,
          eventId: `evt-scope-${index + 2}`,
          receivedAt: `2026-10-18T14:0${index + 1}:00Z`,
          status: 400,
          durationMs: 20,
          headers: {},
          requestBody,
          responseBody: "",
        })),
      ],
    }),
  );
  await page.getByRole("button", { name: "Validate and import" }).click();
  const saved = await page.evaluate(() =>
    localStorage.getItem("payload-clinic.incident.v1"),
  );
  for (let cycle = 0; cycle < 3; cycle++) {
    await page.getByRole("button", { name: /scope-1/ }).click();
    await expect(
      page.getByText("Form fields and text patterns checked.", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByLabel("Redacted request body", { exact: true }),
    ).toHaveText("[email removed]=delivered&token=[removed]");
    if (cycle === 2)
      await page.screenshot({
        path: test.info().outputPath("form-check-scope.png"),
        fullPage: true,
      });
    for (let index = 0; index < plainBodies.length; index++) {
      await page
        .getByRole("button", { name: new RegExp(`scope-${index + 2}`) })
        .click();
      await expect(
        page.getByText(
          "Text patterns only; this body has no JSON or form field checks.",
          { exact: true },
        ),
      ).toBeVisible();
      await expect(
        page.getByLabel("Redacted request body", { exact: true }),
      ).toHaveText(plainBodies[index]);
      if (cycle === 2)
        await page.screenshot({
          path: test.info().outputPath(`text-check-scope-${index + 1}.png`),
          fullPage: true,
        });
    }
    expect(
      await page.evaluate(() =>
        localStorage.getItem("payload-clinic.incident.v1"),
      ),
    ).toBe(saved);
    if (cycle < 2) await page.reload();
  }
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export report" }).click(),
  ]);
  let output = "";
  for await (const chunk of (await download.createReadStream())!)
    output += chunk;
  expect(output).toContain("Form fields and text patterns checked.");
  expect(output.match(/Text patterns only/g)).toHaveLength(2);
  expect(output).not.toMatch(/jane|synthetic-form-973|JSON-like/);
});
