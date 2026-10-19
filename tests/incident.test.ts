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
