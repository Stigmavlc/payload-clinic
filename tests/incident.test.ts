import { describe, expect, it } from "vitest";
import {
  compareAttempts,
  findings,
  importIncident,
  report,
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
      },
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
  expect(output).toContain("Request:\n```json\n{\n");
  expect(output).toContain(
    "Response:\n````text\n```\nrecorded line\n```\n````",
  );
});
