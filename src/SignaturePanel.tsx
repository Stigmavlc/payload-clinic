import { useRef, useState } from "react";
import { LockClosedIcon } from "@radix-ui/react-icons";
import { hmacSha256, timestampAge, verifyStripe } from "./signature";

export function SignaturePanel() {
  const [raw, setRaw] = useState("");
  const [header, setHeader] = useState("");
  const [secret, setSecret] = useState("");
  const [result, setResult] = useState<Awaited<
    ReturnType<typeof verifyStripe>
  > | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const revision = useRef(0);
  function invalidate() {
    revision.current++;
    setResult(null);
    setError("");
  }
  async function sample(expired: boolean) {
    const sampleRevision = ++revision.current;
    const text = '{ "id": "evt-synthetic-628", "type": "booking.confirmed" }';
    const key = "synthetic-demo-key-not-a-live-secret";
    const time = Math.floor(Date.now() / 1000) - (expired ? 900 : 0);
    const digest = await hmacSha256(
      new TextEncoder().encode(key),
      `${time}.${text}`,
    );
    if (sampleRevision !== revision.current) return;
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
    invalidate();
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
            invalidate();
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
            invalidate();
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
            invalidate();
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
            const verificationRevision = revision.current;
            setWorking(true);
            setError("");
            setResult(null);
            try {
              const checked = await verifyStripe(
                raw,
                header,
                secret,
                Math.floor(Date.now() / 1000),
              );
              if (verificationRevision === revision.current) setResult(checked);
            } catch (e) {
              if (verificationRevision === revision.current)
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
            invalidate();
            try {
              setRaw(JSON.stringify(JSON.parse(raw)));
              setResult(null);
              setError("");
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
          <div
            className={`result ${!result.fresh || !result.matches ? "error" : ""}`}
          >
            <h3>
              {!result.fresh
                ? "Timestamp outside tolerance"
                : result.matches
                  ? "Signature matches"
                  : "Signature does not match"}
            </h3>
            <p>
              {result.fresh
                ? "Timestamp is within the 300 second tolerance."
                : `Timestamp is outside the 300 second tolerance (${timestampAge(result.ageSeconds)}).`}
            </p>
            <p className="help mt-2">
              Digest comparison:{" "}
              {result.matches
                ? "matches the supplied bytes and key"
                : "does not match the supplied bytes and key"}
              .
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
