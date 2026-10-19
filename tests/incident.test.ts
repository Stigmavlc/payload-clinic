import { describe, expect, it } from "vitest";
import {
  compareAttempts,
  findings,
  formatGap,
  importIncident,
  report,
  responseStatus,
} from "../src/incident";
const fixture = () => ({
  title: "Booking confirmation delivery",
  senderTimeoutMs: 4000,
  attempts: [
    {
      id: "attempt-02",
      eventId: "evt-booking-47",
      receivedAt: "2026-10-18T09:01:00Z",
      status: 200,
      durationMs: 4200,
      headers: {
        Authorization: "Bearer private-value",
        "content-type": "application/json",
      } as Record<string, string>,
      requestBody:
        '{"id":"evt-booking-47","email":"test@example.com","access_token":"private-value"}',
      responseBody: '{"result":"queued"}',
    },
    {
      id: "attempt-01",
      eventId: "evt-booking-47",
      receivedAt: "2026-10-18T09:00:00Z",
      status: 503,
      durationMs: 180,
      headers: {},
      requestBody: '{"id":"evt-booking-47","amount":1750}',
      responseBody: "Service unavailable",
    },
  ],
});
it("keeps missing, boolean and empty sensitive values with no invented removals", () => {
  const source = fixture();
  source.attempts = [
    {
      ...source.attempts[1],
      headers: { Authorization: "", "content-type": "application/json" },
      requestBody:
        '{ "receipt_email":null, "email_verified":false, "has_signature":true, "token":"", "total_tokens":42 }',
      responseBody: "email=&token=&qty=2",
    },
  ];
  const incident = importIncident(JSON.stringify(source));
  expect(incident.attempts[0].requestBody).toBe(
    '{ "receipt_email":null, "email_verified":false, "has_signature":true, "token":"", "total_tokens":"[removed]" }',
  );
  expect(incident.attempts[0].responseBody).toBe(
    source.attempts[0].responseBody,
  );
  expect(incident.attempts[0].headers).toEqual(source.attempts[0].headers);
  expect(incident.redactions).toEqual([
    "attempt 1.requestBody.total_tokens: sensitive field",
  ]);
  const reopened = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  expect(reopened).toEqual(incident);
  expect(report(reopened)).toContain('"receipt_email":null');
  expect(report(reopened)).toContain("email=&token=&qty=2");
});
it("retains repeated JSON names and their exact redaction log across two reopens", () => {
  const source = fixture();
  source.attempts = [
    {
      ...source.attempts[1],
      requestBody: '{"status":"ok","status":"failed","amount":10.50}',
      responseBody: '{"token":"a","token":"b"}',
    },
  ];
  const incident = importIncident(JSON.stringify(source));
  expect(incident.attempts[0].requestBody).toBe(source.attempts[0].requestBody);
  expect(incident.attempts[0].responseBody).toBe(
    '{"token":"[removed]","token":"[removed]"}',
  );
  expect(incident.redactions).toEqual([
    "attempt 1.responseBody.token: sensitive field",
  ]);
  const first = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  const second = importIncident(JSON.stringify(first), {
    restoreRedactions: true,
  });
  expect(first).toEqual(incident);
  expect(second).toEqual(incident);
});
it("exports kept and removed headers and labels an absent response body", () => {
  const source = fixture();
  source.attempts[0].responseBody = "";
  const output = report(importIncident(JSON.stringify(source)));
  expect(output).toContain('"content-type": "application/json"');
  expect(output).toContain('"Authorization": "[removed]"');
  expect(output).toContain("No headers recorded");
  expect(output).toContain("(empty response body)");
  expect(output).not.toContain("private-value");
});
it("uses the same missing response label in comparisons and reports", () => {
  const incident = importIncident(JSON.stringify(fixture()));
  incident.attempts[1].status = null;
  expect(responseStatus(null)).toBe("No response recorded");
  expect(
    compareAttempts(incident.attempts[0], incident.attempts[1]).status,
  ).toBe("503 → No response recorded");
  expect(report(incident)).toContain("Status: No response recorded;");
});
it("rejects different Message-ID events that merge but preserves genuine repeats", () => {
  const source = fixture();
  source.attempts[0].eventId = "20261018100000.1.AB12CD@mg.example.test";
  source.attempts[1].eventId = "20261018100000.2.EF34GH@mg.example.test";
  expect(() => importIncident(JSON.stringify(source))).toThrow(
    "Different event identifiers become identical",
  );
  source.attempts[1].eventId = source.attempts[0].eventId;
  const incident = importIncident(JSON.stringify(source));
  expect(
    compareAttempts(incident.attempts[0], incident.attempts[1]).sameEvent,
  ).toBe(true);
  expect(
    findings(incident, incident.attempts[0]).some(
      (f) => f.title === "Event identifier repeated",
    ),
  ).toBe(true);
});
describe("incident import and evidence", () => {
  it("orders attempts chronologically and compares the actual gap", () => {
    const x = importIncident(JSON.stringify(fixture()));
    expect(x.attempts[0].id).toBe("attempt-01");
    expect(compareAttempts(x.attempts[0], x.attempts[1])).toMatchObject({
      gapMs: 60000,
      sameEvent: true,
      sameBody: false,
    });
  });
  it("redacts sensitive headers, JSON fields, emails and repeated secrets before persistence or report", () => {
    const data = fixture();
    data.title = "test@example.com";
    data.attempts[1].responseBody = "private-value";
    const x = importIncident(JSON.stringify(data));
    for (const value of [JSON.stringify(x), report(x)]) {
      expect(value).not.toContain("test@example.com");
      expect(value).not.toContain("private-value");
    }
    expect(x.redactions.length).toBeGreaterThan(2);
  });
  it("distinguishes HTTP acceptance, processing uncertainty and sender time limit", () => {
    const x = importIncident(JSON.stringify(fixture()));
    const f = findings(x, x.attempts[1]);
    expect(
      f.some((v) => v.title === "Response reached the sender’s time limit"),
    ).toBe(true);
    expect(f.some((v) => v.detail.includes("does not establish"))).toBe(true);
    expect(f.some((v) => v.title === "Event identifier repeated")).toBe(true);
  });
  it("accepts an invalid body as evidence and flags it without inventing a root cause", () => {
    const data = fixture();
    data.attempts[0].requestBody = "{ broken";
    const x = importIncident(JSON.stringify(data));
    expect(
      findings(x, x.attempts[1]).some(
        (f) => f.title === "Request body is not valid JSON",
      ),
    ).toBe(true);
  });
  it.each([
    { ...fixture(), senderTimeoutMs: 0 },
    { ...fixture(), attempts: [] },
    { ...fixture(), attempts: [{ ...fixture().attempts[0], status: 777 }] },
    {
      ...fixture(),
      attempts: [{ ...fixture().attempts[0], receivedAt: "yesterday" }],
    },
    { ...fixture(), attempts: [{ ...fixture().attempts[0], durationMs: -1 }] },
    { ...fixture(), attempts: [fixture().attempts[0], fixture().attempts[0]] },
  ])("rejects malformed incident structure", (input) =>
    expect(() => importIncident(JSON.stringify(input))).toThrow(),
  );
  it("rejects oversized input before parsing", () =>
    expect(() => importIncident(" ".repeat(1_000_001))).toThrow(
      "larger than 1 MB",
    ));
  it("does not import unrecognised data into the persistent model", () => {
    const x = importIncident(
      JSON.stringify({ ...fixture(), secretNotes: "should not appear" }),
    );
    expect(JSON.stringify(x)).not.toContain("should not appear");
  });
});

it("redacts private object keys throughout nested diagnostic paths", () => {
  const data = fixture();
  data.attempts[0].requestBody = JSON.stringify({
    "person@example.test": { secret: "hidden-value" },
  });
  const incident = importIncident(JSON.stringify(data));
  expect(JSON.stringify(incident)).not.toContain("person@example.test");
  expect(report(incident)).not.toContain("hidden-value");
});

it("preserves ordinary values, longer words and field names during repeated-secret redaction", () => {
  const data = fixture();
  data.attempts[0].requestBody = JSON.stringify({
    token_status: "active",
    token: "private-value",
    state: "inactive",
    path: "/hooks/active-orders",
    "private-value": "diagnostic label",
    detail: "private-value-suffix",
    exact: "private-value",
  });
  const value = importIncident(JSON.stringify(data));
  const body = JSON.parse(value.attempts[1].requestBody);
  expect(body.state).toBe("inactive");
  expect(body.path).toBe("/hooks/active-orders");
  expect(body["private-value"]).toBe("diagnostic label");
  expect(body.detail).toBe("private-value-suffix");
  expect(body.exact).toBe("[secret removed]");
});

it.each([
  "whsec_syntheticSigning72648",
  "rk_live_syntheticRestricted8264",
  "rk_test_syntheticRestricted7352",
])("removes recognised Stripe credential %s", (credential) => {
  const data = fixture();
  data.attempts[0].responseBody = `failure with ${credential}`;
  const value = importIncident(JSON.stringify(data));
  expect(JSON.stringify(value)).not.toContain(credential);
  expect(report(value)).not.toContain(credential);
});
it.each([
  ["Authorization", "Bearer credential-value-7364", "credential-value-7364"],
  [
    "Authorization",
    "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
    "YWxhZGRpbjpvcGVuc2VzYW1l",
  ],
  ["Stripe-Signature", "t=1000,v1=" + "a1".repeat(32), "a1".repeat(32)],
])("removes a bare credential repeated from %s", (name, header, credential) => {
  const data = fixture();
  data.attempts[0].headers = { [name]: header };
  data.attempts[0].responseBody = `failure with ${credential}`;
  const value = importIncident(JSON.stringify(data));
  expect(JSON.stringify(value)).not.toContain(credential);
  expect(report(value)).not.toContain(credential);
});
it("redacts form fields and their repeated values while keeping ordinary fields", () => {
  const data = fixture();
  data.attempts[0].requestBody =
    "token=synthetic-token-8364&password=synthetic-password-9274&quantity=3&note=synthetic-token-8364";
  const value = importIncident(JSON.stringify(data));
  expect(JSON.stringify(value)).not.toContain("synthetic-token-8364");
  expect(report(value)).not.toContain("synthetic-password-9274");
  const form = new URLSearchParams(value.attempts[1].requestBody);
  expect(form.get("quantity")).toBe("3");
  expect(form.get("note")).toBe("[secret removed]");
});

it("exports readable fenced bodies even when recorded text contains a Markdown fence", () => {
  const data = fixture();
  data.attempts[0].responseBody = "```\nrecorded line\n```";
  const output = report(importIncident(JSON.stringify(data)));
  expect(output).toContain("Request:\n```json\n{");
  expect(output).toContain(
    "Response:\n````text\n```\nrecorded line\n```\n````",
  );
});

it("retains ordinary Basic and Bearer phrases as investigation evidence", () => {
  const data = fixture();
  data.title = "Basic plan renewals rejected";
  data.attempts[0].headers = {};
  data.attempts[0].requestBody = '{"plan":"Basic monthly"}';
  data.attempts[0].responseBody =
    'Bearer token expired. Basic authentication required. The bearer of this order. WWW-Authenticate: Basic realm="example". This endpoint requires Bearer authentication. Expected Bearer authorization. Invalid Bearer credentials. Bearer authentication/JWT';
  const incident = importIncident(JSON.stringify(data));
  expect(incident.title).toBe(data.title);
  expect(JSON.parse(incident.attempts[1].requestBody).plan).toBe(
    "Basic monthly",
  );
  expect(incident.attempts[1].responseBody).toBe(data.attempts[0].responseBody);
  expect(incident.redactions).toEqual([]);
});
it.each([
  "Bearer synthetic-credential-82364",
  "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
])(
  "removes credential-shaped %s text without deleting its scheme",
  (credential) => {
    const data = fixture();
    data.attempts[0].responseBody = credential;
    const incident = importIncident(JSON.stringify(data));
    expect(incident.attempts[1].responseBody).toBe(
      credential.split(" ")[0] + " [credential removed]",
    );
  },
);

it("describes the limits of report redaction honestly", () => {
  const data = fixture();
  data.attempts[0].responseBody = "opaque-example-credential-48152";
  const output = report(importIncident(JSON.stringify(data)));
  expect(output).toContain("opaque-example-credential-48152");
  expect(output).toContain(
    "Recognised patterns were removed; review the report content before sharing.",
  );
  expect(output).not.toContain("secrets are never included");
});

it("imports and reopens a near-limit attachment without repeated email rescanning", () => {
  const data = fixture();
  data.attempts[0].requestBody = JSON.stringify({
    attachment: "A".repeat(950000),
  });
  const text = JSON.stringify(data);
  expect(new TextEncoder().encode(text).length).toBeLessThan(1000000);
  const started = performance.now();
  const incident = importIncident(text);
  const reopened = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  expect(JSON.parse(reopened.attempts[1].requestBody).attachment).toHaveLength(
    950000,
  );
  expect(performance.now() - started).toBeLessThan(1500);
});

it("preserves large numeric identifiers and number spellings across import, reload, comparison and report", () => {
  const data = fixture();
  data.attempts[0].requestBody =
    '{ "id": 12345678901234567890, "amount": 10.50, "scale": 1e2, "zero": -0, "secret": {"value": 3} }';
  data.attempts[1].requestBody =
    '{ "id": 12345678901234567891, "amount": 10.50, "scale": 1e2, "zero": -0, "secret": {"value": 3} }';
  const incident = importIncident(JSON.stringify(data));
  const expected = data.attempts[0].requestBody.replace(
    '{"value": 3}',
    '"[removed]"',
  );
  expect(incident.attempts[1].requestBody).toBe(expected);
  expect(
    compareAttempts(incident.attempts[0], incident.attempts[1]).sameBody,
  ).toBe(false);
  const reopened = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  expect(reopened.attempts[1].requestBody).toBe(expected);
  expect(report(reopened)).toContain(expected);
});
it("redacts nested and escaped JSON string tokens without normalising surrounding evidence", () => {
  const data = fixture();
  data.attempts[0].requestBody = String.raw`{"items":[{"e\u006dail":"person@example.test","note":"a \\\"quoted\\\" value"}],"large":98765432109876543210}`;
  const incident = importIncident(JSON.stringify(data));
  const result = incident.attempts[1].requestBody;
  expect(result).not.toContain("person@example.test");
  expect(result).toContain('"large":98765432109876543210');
  expect(JSON.parse(result).items[0].note).toBe(
    JSON.parse(data.attempts[0].requestBody).items[0].note,
  );
});

it("keeps the original redaction log order for multiple attempts and sensitive form fields on reload", () => {
  const data = fixture();
  data.title = "Email person@example.test";
  data.attempts[1].requestBody =
    "token=second-secret-7364&quantity=3&note=second-secret-7364";
  const incident = importIncident(JSON.stringify(data));
  const reopened = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  const reopenedAgain = importIncident(JSON.stringify(reopened), {
    restoreRedactions: true,
  });
  expect(reopened.redactions).toEqual(incident.redactions);
  expect(reopenedAgain).toEqual(reopened);
  expect(reopened.attempts).toEqual(incident.attempts);
});

it("reopens an expanded saved title and redaction log beyond the raw import limit", () => {
  const data = fixture();
  data.title = "a@b.co c@d.co " + "x".repeat(166);
  data.attempts[0].requestBody = JSON.stringify(
    Array.from({ length: 7600 }, (_, i) => ({ email: `p${i}@x.co`, n: i })),
  );
  const incident = importIncident(JSON.stringify(data));
  expect(incident.title.length).toBeGreaterThan(180);
  // Saved logs and replacement labels can grow beyond the incoming file size.
  const expanded = {
    ...incident,
    redactions: [
      ...incident.redactions,
      ...Array.from(
        { length: 10000 },
        (_, i) => `field-${i}: ` + "r".repeat(80),
      ),
    ],
  };
  expect(JSON.stringify(expanded).length).toBeGreaterThan(1000000);
  expect(
    importIncident(JSON.stringify(expanded), { restoreRedactions: true }),
  ).toEqual(expanded);
});
it("rejects identifiers that collide after redaction before they can be saved", () => {
  const data = fixture();
  data.attempts[0].id = "a@example.test";
  data.attempts[1].id = "b@example.test";
  expect(() => importIncident(JSON.stringify(data))).toThrow(
    "identical after redaction",
  );
});

it("redacts a near-limit email event batch with a shared repeated-value lookup", () => {
  const data = fixture();
  const rows = Array.from({ length: 6800 }, (_, i) => ({
    email: `recipient-${i}@example.test`,
    event: "delivered",
    messageId: `message-${i}`,
    detail: "synthetic delivery record",
  }));
  data.attempts[0].requestBody = JSON.stringify(rows);
  data.attempts[1].responseBody =
    "Contact recipient-4150@example.test for the record";
  const text = JSON.stringify(data);
  expect(text.length).toBeGreaterThan(850000);
  expect(new TextEncoder().encode(text).length).toBeLessThan(1000000);
  const started = performance.now();
  const incident = importIncident(text);
  const reopened = importIncident(JSON.stringify(incident), {
    restoreRedactions: true,
  });
  expect(performance.now() - started).toBeLessThan(1500);
  expect(reopened).toEqual(incident);
  expect(report(incident)).not.toContain("recipient-4150@example.test");
});
it("uses longest whole repeated credentials without changing adjacent longer tokens", () => {
  const data = fixture();
  data.attempts[0].headers = {
    token: "example-token-123",
    secret: "example-token-123.extra",
  };
  data.attempts[0].responseBody =
    "example-token-123.extra example-token-123 example-token-123-longer";
  const incident = importIncident(JSON.stringify(data));
  expect(incident.attempts[1].responseBody).toBe(
    "[secret removed] [secret removed] example-token-123-longer",
  );
});

it("keeps sentence punctuation after removing a recognised Bearer credential", () => {
  const data = fixture();
  data.attempts[0].responseBody = "Rejected Bearer synthetic-credential-82364.";
  expect(importIncident(JSON.stringify(data)).attempts[1].responseBody).toBe(
    "Rejected Bearer [credential removed].",
  );
});

it("numbers redaction paths in the same chronological order as the timeline and report", () => {
  const incident = importIncident(JSON.stringify(fixture()));
  expect(incident.attempts.map((a) => a.id)).toEqual([
    "attempt-01",
    "attempt-02",
  ]);
  expect(incident.redactions).toContain(
    "attempt 2.headers.Authorization: sensitive field",
  );
  expect(incident.redactions).toContain(
    "attempt 2.requestBody.email: sensitive field",
  );
  expect(
    incident.redactions.some((line) => line.startsWith("attempt 1.")),
  ).toBe(false);
  expect(report(incident)).toContain("## Attempt 2: attempt-02");
  expect(
    importIncident(JSON.stringify(incident), { restoreRedactions: true })
      .redactions,
  ).toEqual(incident.redactions);
});

it.each([
  "Body=Hello%20world!&From=%2b447700900123",
  "error=invalid signature, retry later",
  "quantity=1&quantity=2&flag&value=a%2fb%20c+more",
])("preserves unchanged form evidence exactly: %s", (body) => {
  const data = fixture();
  data.attempts[0].requestBody = body;
  const incident = importIncident(JSON.stringify(data));
  expect(incident.attempts[1].requestBody).toBe(body);
  expect(
    importIncident(JSON.stringify(incident), { restoreRedactions: true })
      .attempts[1].requestBody,
  ).toBe(body);
});
it("patches only removed form values and leaves their replacements readable", () => {
  const data = fixture();
  data.attempts[0].requestBody =
    "Body=Hello%20world!&From=%2b447700900123&token=private-value&note=private-value&flag";
  const incident = importIncident(JSON.stringify(data));
  const expected =
    "Body=Hello%20world!&From=%2b447700900123&token=[removed]&note=[secret removed]&flag";
  expect(incident.attempts[1].requestBody).toBe(expected);
  expect(report(incident)).toContain(expected);
  expect(
    importIncident(JSON.stringify(incident), { restoreRedactions: true }),
  ).toEqual(incident);
});

it.each([
  [0, "0 seconds"],
  [1000, "1 second"],
  [1500, "1.5 seconds"],
  [120000, "2 minutes"],
  [21600000, "6 hours"],
  [86401000, "1 day, 1 second"],
  [-86401000, "minus 1 day, 1 second"],
])("formats retry spacing %s consistently", (gap, expected) =>
  expect(formatGap(gap as number)).toBe(expected),
);

it("keeps email-named JSON keys, headers and form fields unchanged across two reopens", () => {
  const source = fixture();
  source.attempts[0].headers = {
    "X-jane@example.test": "delivered",
    "X-joe@example.test": "bounced",
  };
  source.attempts[0].requestBody = JSON.stringify({
    results: {
      "jane@example.test": { status: "delivered" },
      "joe@example.test": { status: "bounced", reason: "mailbox full" },
      "[email removed]": { status: "already redacted" },
    },
  });
  source.attempts[0].responseBody =
    "jane%40example.test=delivered&joe%40example.test=bounced";
  const imported = importIncident(JSON.stringify(source));
  const first = importIncident(JSON.stringify(imported), {
    restoreRedactions: true,
  });
  const second = importIncident(JSON.stringify(first), {
    restoreRedactions: true,
  });
  expect(first).toEqual(imported);
  expect(second).toEqual(imported);
  const attempt = imported.attempts[1];
  expect(Object.values(attempt.headers)).toEqual(["delivered", "bounced"]);
  expect(Object.keys(attempt.headers)).toHaveLength(2);
  expect(Object.values(JSON.parse(attempt.requestBody).results)).toEqual([
    { status: "delivered" },
    { status: "bounced", reason: "mailbox full" },
    { status: "already redacted" },
  ]);
  expect(attempt.responseBody).toContain("=delivered");
  expect(attempt.responseBody).toContain("=bounced");
  expect(
    imported.redactions.every((line) => !line.startsWith("field name:")),
  ).toBe(true);
});

it.each(["\n", "\r\n", " ", "\t"])(
  "redacts form bodies with surrounding whitespace %j before persistence",
  (edge) => {
    const source = fixture();
    source.attempts = [
      {
        ...source.attempts[1],
        requestBody:
          edge + "AccountSid=AC0000&token=synthetic-secret-812&qty=2" + edge,
        responseBody: edge + "password=synthetic-password-813&ok=1" + edge,
      },
    ];
    const incident = importIncident(JSON.stringify(source));
    expect(incident.attempts[0].requestBody).toBe(
      edge + "AccountSid=AC0000&token=[removed]&qty=2" + edge,
    );
    expect(incident.attempts[0].responseBody).toBe(
      edge + "password=[removed]&ok=1" + edge,
    );
    expect(incident.redactions).toEqual([
      "attempt 1.requestBody.token: sensitive form field",
      "attempt 1.responseBody.password: sensitive form field",
    ]);
    const reopened = importIncident(JSON.stringify(incident), {
      restoreRedactions: true,
    });
    expect(reopened).toEqual(incident);
    expect(report(reopened)).not.toMatch(/synthetic-secret|synthetic-password/);
  },
);
