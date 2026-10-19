# Payload Clinic

Payload Clinic helps small software support teams explain failed webhook deliveries. Bring synthetic or redacted receiving-side records into one local workspace, compare attempts and prepare an incident report without copying production secrets into an online service.

[Open the demo](https://stigmavlc.github.io/payload-clinic/) · [Run locally](#run-locally) · [Incident format](#incident-format)

![Receiving-side delivery evidence](docs/screenshots/evidence.png)

![Comparison of the slow response and retry](docs/screenshots/comparison.png)

![A valid synthetic signature and timestamp](docs/screenshots/signature.png)

## Try a short investigation

1. Open **Slow response and retries**. The first receiving-side record contains a 503 response.
2. Select `delivery-7b`. Its 3,274 ms duration exceeds the supplied 3,000 ms sender time limit. The receiver returned 202, but these records alone do not prove what the sender received or whether downstream work completed.
3. Open **Compare attempts** and compare that record with `delivery-7c`. Check the recorded gap, event identifier, body and response.
4. Export a redacted Markdown report. It contains the records, observations, suggested checks and redaction log, with no signature-checker inputs.
5. In **Signature check**, load a signed synthetic sample and verify it. Reformat the JSON and verify again to see why the original bytes matter. The expired sample demonstrates the separate timestamp check.

The second incident, **Changed request contract**, contains malformed JSON followed by a 422 response about a field type. Use it to practise checking the payload against the endpoint contract and deciding which receiving-side evidence to request next.

## What it does

- Validates incident structure before import, with clear errors for malformed input.
- Orders receiving-side records by timestamp and shows gaps between attempts.
- Separates HTTP status observations from investigation checks, including slow responses and repeated event identifiers.
- Compares event identifiers, timing, HTTP status and request bodies after redaction.
- Redacts recognised secret fields, credential patterns and email addresses before browser storage or report export.
- Verifies Stripe-style HMAC SHA-256 signatures using the original UTF-8 body and timestamp, with a five-minute tolerance.

The examples are fictional. Observations describe the supplied records; investigation checks identify the evidence still needed from the sender or receiver.

## Data handling

Use synthetic or already redacted records and inspect the result before sharing it. Input stays in the browser. The static host receives normal page and asset requests; incident and signature inputs remain local.

Sensitive JSON fields and headers are removed when their names contain authorization, cookie, signature, token, secret, password, API key or email. The same name checks apply to form-encoded bodies in `key=value&key=value` format. Text checks cover email addresses, long Bearer tokens containing credential punctuation or digits, valid long Basic base64 credentials containing a decoded colon, JWT-shaped strings, Stripe `sk_`, `pk_` and `rk_` live/test keys, and `whsec_` signing secrets. Bare Bearer/Basic credentials and Stripe v1 digests are also collected from headers for repeated-value checks.

Repeated matching applies to unbroken values of at least 12 characters containing a number or credential punctuation, including long hexadecimal digests. It respects token boundaries and leaves ordinary field names intact. Email and credential patterns are still removed from field names. Invalid JSON bodies are retained as redacted text; recognised form bodies are encoded again after redaction. Unknown incident properties are discarded.

These checks cover particular patterns. Names, addresses, encoded values, unfamiliar credential formats and private business details can remain. The redaction log records recognised removals and is preserved when reopening a saved incident.

The redacted incident and its log are saved in `localStorage` under `payload-clinic.incident.v1`. This storage is unencrypted and readable by scripts on the same origin. **Remove saved copy** deletes it, while the current view stays in memory. Importing a record or choosing an example saves the new incident. Clearing site storage also removes the saved copy.

Signing inputs use separate, temporary component memory. Leaving **Signature check** or pressing **Clear sensitive inputs** clears them. Storage and reports contain incident evidence only. A digest match confirms the supplied key and bytes; the timestamp must also pass the five-minute check. Event authenticity and successful processing require evidence from the production systems.

## Incident format

Import a JSON file or paste a JSON object. The whole file is limited to 1 MB, with 1 to 100 attempts and a title of 1 to 180 characters. Unknown properties are ignored. Header names map to strings. Attempt identifiers must be unique; event identifiers may repeat.

```json
{
  "title": "Booking confirmation investigation",
  "senderTimeoutMs": 3000,
  "attempts": [
    {
      "id": "delivery-01",
      "eventId": "evt-booking-624",
      "receivedAt": "2026-10-18T10:42:16Z",
      "status": 503,
      "durationMs": 143,
      "headers": { "content-type": "application/json" },
      "requestBody": "{\"id\":\"evt-booking-624\"}",
      "responseBody": "{\"error\":\"upstream_unavailable\"}"
    }
  ]
}
```

`receivedAt` needs an ISO timestamp with a time zone. `status` is an integer from 100 to 599, or `null` if no HTTP response was recorded. Durations cannot be negative. Supply the sender’s documented positive time limit in `senderTimeoutMs`. Bodies are strings so malformed JSON can be retained as evidence.

## Run locally

Use Node.js 22 and npm.

```sh
npm ci
npm run dev
```

Open the local address printed by Vite, including `/payload-clinic/`.

```sh
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

For Linux environments without browser system libraries, use `npx playwright install --with-deps chromium`. The browser tests start their own local Vite server on port 4173. `npm run preview` serves a production build.

## Verification

The test suite covers chronological ordering, status interpretation, sender time limits, invalid JSON, malformed import structures, duplicate identifiers, redaction across bodies and nested object keys, repeated secrets and report content. Cryptographic tests include RFC 4231 test case 1 and the supplied Stripe signing format, with changed bytes, missing or malformed signatures and expired timestamps.

Browser tests exercise a complete investigation and export, invalid and valid imports, redacted persistence and the full redaction log across reload, transient signing inputs, an expired timestamp, a 390 px layout, and keyboard focus containment and restoration. CI installs dependencies, runs the unit tests, builds the app and runs Chromium tests. Publishing depends on that verification job succeeding for the same commit.

Screenshots show the application running with synthetic records at 1440 px. Run `CAPTURE_DOCS=1 npm run test:browser -- --grep "capture the three"` to refresh them in `docs/screenshots/`.

## Design and implementation

React and TypeScript provide a small static application. Vite builds it; Tailwind CSS and local styles provide the layout; Radix icons identify actions without a remote icon service. All fonts use the system stack.

- `src/incident.ts`: import validation, redaction, observations, comparisons and report generation.
- `src/signature.ts`: Web Crypto HMAC and Stripe header verification.
- `src/SignaturePanel.tsx`: short-lived signing inputs and synthetic examples.
- `src/main.tsx`: timeline, import, persistence and views.
- `tests/`: unit and browser verification.
- `.github/workflows/ci.yml`: verification and GitHub Pages publication.

The application is static and can be served from GitHub Pages. All investigation and cryptographic calculations run in the browser.

## References

- [Stripe: verify webhook signatures](https://docs.stripe.com/webhooks/signature)
- [RFC 4231: HMAC SHA-256 test vectors](https://www.rfc-editor.org/rfc/rfc4231)
- [MDN: Web Crypto sign](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign)

## Licence

MIT. Copyright 2026 Ivan Aguilar.
