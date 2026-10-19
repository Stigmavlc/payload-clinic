import { useState } from "react";
import { LockClosedIcon } from "@radix-ui/react-icons";
import { hmacSha256, verifyStripe } from "./signature";

export function SignaturePanel() {
  const [raw, setRaw] = useState("");
  const [header, setHeader] = useState("");
  const [secret, setSecret] = useState("");
  const [result, setResult] = useState<Awaited<
    ReturnType<typeof verifyStripe>
  > | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  async function sample(expired: boolean) {
    const text = '{ "id": "evt-synthetic-628", "type": "booking.confirmed" }';
    const key = "synthetic-demo-key-not-a-live-secret";
    const time = Math.floor(Date.now() / 1000) - (expired ? 900 : 0);
    const digest = await hmacSha256(
      new TextEncoder().encode(key),
      `${time}.${text}`,
    );
    setRaw(text);
    setSecret(key);
    setHeader(`t=${time},v1=${digest}`);
    setResult(null);
    setError("");
  }
  function clear() {
    setRaw("");
    setHeader("");
    setSecret("");
    setResult(null);
    setError("");
  }
  return (
    <section aria-labelledby="signature-heading" className="space-y-6">
      <div className="flex items-start gap-3">
        <LockClosedIcon className="mt-1 shrink-0" />
        <div>
          <h2 id="signature-heading">Check the original bytes</h2>
          <p className="muted mt-1 max-w-[64ch]">
            Stripe’s signing format uses the timestamp, a full stop and the
            exact raw body. Reformatting JSON changes the signature. This check
            runs in memory and is cleared when you leave this view.
          </p>
        </div>
      </div>
      <div className="notice">
        Use synthetic samples here. Imports elsewhere are redacted and cannot be
        used to verify an original signature. No secret, raw body or signature
        is saved or exported.
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="secondary" onClick={() => void sample(false)}>
          Load signed sample
        </button>
        <button className="secondary" onClick={() => void sample(true)}>
          Load expired sample
        </button>
      </div>
      <label className="field">
        Raw request body
        <textarea
          rows={5}
          value={raw}
          spellCheck={false}
          onChange={(e) => {
            setRaw(e.target.value);
            setResult(null);
          }}
        />
        <span className="help">
          Keep every space, line break and character as received.
        </span>
      </label>
      <label className="field">
        Stripe-Signature header
        <textarea
          rows={3}
          spellCheck={false}
          value={header}
          onChange={(e) => {
            setHeader(e.target.value);
            setResult(null);
          }}
        />
      </label>
      <label className="field">
        Signing secret
        <input
          type="password"
          autoComplete="off"
          value={secret}
          onChange={(e) => {
            setSecret(e.target.value);
            setResult(null);
          }}
        />
        <span className="help">
          Session memory only. Clearing the view removes these inputs.
        </span>
      </label>
      <div className="flex flex-wrap gap-2">
        <button
          disabled={working}
          className="primary"
          onClick={async () => {
            setWorking(true);
            setError("");
            setResult(null);
            try {
              setResult(
                await verifyStripe(
                  raw,
                  header,
                  secret,
                  Math.floor(Date.now() / 1000),
                ),
              );
            } catch (e) {
              setError(
                e instanceof Error ? e.message : "Signature check failed.",
              );
            } finally {
              setWorking(false);
            }
          }}
        >
          {working ? "Checking bytes…" : "Verify signature"}
        </button>
        <button
          className="secondary"
          onClick={() => {
            try {
              setRaw(JSON.stringify(JSON.parse(raw)));
              setResult(null);
            } catch {
              setError(
                "The body cannot be reformatted because it is not valid JSON.",
              );
            }
          }}
        >
          Reformat JSON to compare
        </button>
        <button className="quiet" onClick={clear}>
          Clear sensitive inputs
        </button>
      </div>
      <div aria-live="polite">
        {error && <p className="error">{error}</p>}
        {result && (
          <div className="result">
            <h3>
              {result.matches
                ? "Signature matches"
                : "Signature does not match"}
            </h3>
            <p>
              {result.fresh
                ? "Timestamp is within the 300 second tolerance."
                : `Timestamp is outside the 300 second tolerance (${Math.abs(result.ageSeconds)} seconds from now).`}
            </p>
            <p className="help mt-2">
              A matching digest with an expired timestamp is not a valid fresh
              delivery. This is a diagnostic check, not a production webhook
              receiver.
            </p>
          </div>
        )}
      </div>
      <p className="help">
        Scheme:{" "}
        <a
          href="https://docs.stripe.com/webhooks/signature"
          target="_blank"
          rel="noreferrer"
        >
          Stripe webhook signatures
        </a>
        . Cryptographic primitive tested against{" "}
        <a
          href="https://www.rfc-editor.org/rfc/rfc4231"
          target="_blank"
          rel="noreferrer"
        >
          RFC 4231
        </a>
        .
      </p>
    </section>
  );
}
