import { importIncident } from "./incident";
export const sampleText = JSON.stringify(
  {
    title: "Booking confirmation: retry after a slow response",
    senderTimeoutMs: 3000,
    attempts: [
      {
        id: "delivery-7a",
        eventId: "evt-booking-624",
        receivedAt: "2026-10-18T10:42:16.000Z",
        status: 503,
        durationMs: 143,
        headers: {
          "content-type": "application/json",
          authorization: "Bearer synthetic-private-value",
        },
        requestBody: JSON.stringify({
          event: "booking.confirmed",
          id: "evt-booking-624",
          booking: {
            reference: "BK-624",
            email: "marisol@example.test",
            deposit: 3750,
            currency: "GBP",
          },
        }),
        responseBody: JSON.stringify({
          error: "upstream_unavailable",
          requestId: "req-f8c2",
        }),
      },
      {
        id: "delivery-7b",
        eventId: "evt-booking-624",
        receivedAt: "2026-10-18T10:43:16.000Z",
        status: 202,
        durationMs: 3274,
        headers: {
          "content-type": "application/json",
          "x-delivery-attempt": "2",
        },
        requestBody: JSON.stringify({
          event: "booking.confirmed",
          id: "evt-booking-624",
          booking: {
            reference: "BK-624",
            email: "marisol@example.test",
            deposit: 3750,
            currency: "GBP",
          },
        }),
        responseBody: JSON.stringify({
          status: "queued",
          requestId: "req-d2e7",
        }),
      },
      {
        id: "delivery-7c",
        eventId: "evt-booking-624",
        receivedAt: "2026-10-18T10:45:16.000Z",
        status: 200,
        durationMs: 86,
        headers: {
          "content-type": "application/json",
          "x-delivery-attempt": "3",
        },
        requestBody: JSON.stringify({
          event: "booking.confirmed",
          id: "evt-booking-624",
          booking: {
            reference: "BK-624",
            email: "marisol@example.test",
            deposit: 3750,
            currency: "GBP",
          },
        }),
        responseBody: JSON.stringify({
          status: "already_processed",
          requestId: "req-a943",
        }),
      },
    ],
  },
  null,
  2,
);
export const secondSampleText = JSON.stringify(
  {
    title: "Inventory event: request contract changed",
    senderTimeoutMs: 5000,
    attempts: [
      {
        id: "delivery-c1",
        eventId: "evt-stock-318",
        receivedAt: "2026-10-18T14:08:12Z",
        status: 400,
        durationMs: 42,
        headers: {
          "content-type": "application/json",
          cookie: "synthetic-session-cookie",
        },
        requestBody: '{"id":"evt-stock-318","quantity":17,}',
        responseBody: '{"error":"invalid_json"}',
      },
      {
        id: "delivery-c2",
        eventId: "evt-stock-318",
        receivedAt: "2026-10-18T14:10:12Z",
        status: 422,
        durationMs: 58,
        headers: { "content-type": "application/json" },
        requestBody: '{"id":"evt-stock-318","quantity":"seventeen"}',
        responseBody: '{"error":"quantity_must_be_numeric"}',
      },
    ],
  },
  null,
  2,
);
export const sampleIncident = () => ({
  ...importIncident(sampleText),
  example: "booking" as const,
});
