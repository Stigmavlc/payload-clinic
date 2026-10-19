import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ArrowDownIcon,
  ArrowRightIcon,
  CheckIcon,
  FileTextIcon,
  LockClosedIcon,
  UploadIcon,
} from "@radix-ui/react-icons";
import {
  compareAttempts,
  findings,
  formatGap,
  importIncident,
  report,
  responseStatus,
  type Incident,
} from "./incident";
import { sampleIncident, sampleText, secondSampleText } from "./samples";
import { SignaturePanel } from "./SignaturePanel";
import "./style.css";
const STORAGE = "payload-clinic.incident.v1";
function initial(): { incident: Incident; preserveSaved: boolean } {
  let value: string | null;
  try {
    value = localStorage.getItem(STORAGE);
  } catch {
    return { incident: sampleIncident(), preserveSaved: false };
  }
  try {
    return {
      incident: value
        ? importIncident(value, { restoreRedactions: true })
        : sampleIncident(),
      preserveSaved: false,
    };
  } catch {
    return { incident: sampleIncident(), preserveSaved: true };
  }
}
function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}
function App() {
  const [opening] = useState(initial);
  const [incident, setIncident] = useState(opening.incident);
  const [preserveSaved, setPreserveSaved] = useState(opening.preserveSaved);
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useState<"evidence" | "compare" | "signature">(
    "evidence",
  );
  const [compare, setCompare] = useState(1);
  const [importing, setImporting] = useState(false);
  const [input, setInput] = useState("");
  const [error, setError] = useState("");
  const [storageNote, setStorageNote] = useState("");
  const [notice, setNotice] = useState("");
  const modalRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!importing) return;
    const previous =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const dialog = modalRef.current;
    const controls = () =>
      Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          "button:not(:disabled), input:not(:disabled), textarea:not(:disabled), a[href]",
        ) ?? [],
      );
    controls()[0]?.focus();
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setImporting(false);
        setInput("");
        setError("");
      }
      if (event.key === "Tab") {
        const fields = controls(),
          first = fields[0],
          last = fields[fields.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", keyboard);
    return () => {
      document.removeEventListener("keydown", keyboard);
      previous?.focus();
    };
  }, [importing]);
  useEffect(() => {
    if (preserveSaved) {
      setStorageNote(
        "The saved incident could not be reopened and has been kept unchanged. This view shows an example. Importing a new incident will replace the saved copy.",
      );
      return;
    }
    try {
      localStorage.setItem(STORAGE, JSON.stringify(incident));
      setStorageNote("Redacted incident saved on this browser.");
    } catch {
      setStorageNote(
        "Browser storage is unavailable. Export the redacted report before closing.",
      );
    }
  }, [incident, preserveSaved]);
  const current =
    incident.attempts[Math.min(selected, incident.attempts.length - 1)];
  const other =
    incident.attempts[Math.min(compare, incident.attempts.length - 1)];
  const differences = compareAttempts(current, other);
  function load(text: string, example?: "booking" | "inventory") {
    try {
      const safe = importIncident(text);
      if (!example) setPreserveSaved(false);
      setIncident({ ...safe, ...(example ? { example } : {}) });
      setSelected(0);
      setCompare(Math.min(1, safe.attempts.length - 1));
      setError("");
      setInput("");
      setImporting(false);
      setTab("evidence");
      setNotice(
        "Incident imported and redacted. Review the removed fields before sharing.",
      );
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Could not import this incident.",
      );
    }
  }
  return (
    <div className="shell">
      <header className="topbar">
        <a href="#main" className="skip-link">
          Skip to investigation
        </a>
        <div className="brand">
          <span className="brand-mark">pc</span>
          <span>Payload Clinic</span>
        </div>
        <div className="local-indicator">
          <LockClosedIcon />
          <span>Local workspace</span>
        </div>
        <a
          className="repo-link"
          href="https://github.com/Stigmavlc/payload-clinic"
          target="_blank"
          rel="noreferrer"
        >
          Source <ArrowRightIcon />
        </a>
      </header>
      <div className="workspace">
        <aside className="sidebar" aria-label="Delivery timeline">
          <div className="sidebar-heading">
            <span className="eyebrow">Webhook records</span>
            <h1>Delivery timeline</h1>
          </div>
          <div className="sample-control">
            <label htmlFor="samples" className="eyebrow">
              Synthetic examples
            </label>
            <select
              id="samples"
              value={incident.example ?? "custom"}
              onChange={(e) =>
                load(
                  e.target.value === "booking" ? sampleText : secondSampleText,
                  e.target.value as "booking" | "inventory",
                )
              }
            >
              <option value="custom" disabled>
                Imported incident
              </option>
              <option value="booking">Slow response and retries</option>
              <option value="inventory">Changed request contract</option>
            </select>
            {incident.example && (
              <span className="help">
                Fictional delivery records, safe to explore.
              </span>
            )}
          </div>
          <div className="timeline-label">
            <span className="eyebrow">Received attempts</span>
            <span className="mono">{incident.attempts.length}</span>
          </div>
          <ol className="timeline">
            {incident.attempts.map((a, i) => (
              <li key={a.id}>
                <button
                  className={`attempt ${i === selected ? "selected" : ""}`}
                  aria-pressed={i === selected}
                  onClick={() => {
                    setSelected(i);
                    if (tab === "signature") setTab("evidence");
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span className="mono text-xs">
                      {new Date(a.receivedAt)
                        .toISOString()
                        .slice(0, 19)
                        .replace("T", " ")}{" "}
                      UTC
                    </span>
                    <span
                      className={`status status-${a.status === null ? "none" : Math.floor(a.status / 100)}`}
                    >
                      {responseStatus(a.status)}
                    </span>
                  </div>
                  <strong>
                    Attempt {i + 1}: {a.id}
                  </strong>
                  <div className="flex justify-between text-xs muted">
                    <span>{a.eventId}</span>
                    <span className="mono">
                      {a.durationMs.toLocaleString()} ms
                    </span>
                  </div>
                  {i > 0 && (
                    <span className="gap-note">
                      {formatGap(
                        Date.parse(a.receivedAt) -
                          Date.parse(incident.attempts[i - 1].receivedAt),
                      )}{" "}
                      after previous attempt
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ol>
          <button
            className="secondary w-full justify-center"
            onClick={() => {
              setImporting(true);
              setError("");
            }}
          >
            <UploadIcon /> Import incident
          </button>
          <div className="sidebar-foot">
            <p className="help">{storageNote}</p>
            <button
              className="quiet mt-2 text-left"
              onClick={() => {
                try {
                  localStorage.removeItem(STORAGE);
                  setStorageNote(
                    "Saved copy removed. This view remains in memory until another incident is loaded.",
                  );
                } catch {
                  setStorageNote("The browser did not allow storage access.");
                }
              }}
            >
              Remove saved copy
            </button>
          </div>
        </aside>
        <main id="main" className="main">
          <div className="main-heading">
            <div>
              <div className="eyebrow flex items-center gap-2">
                <span className="sample-dot" /> Delivery investigation
              </div>
              <h2>{incident.title}</h2>
              <p className="muted">
                Sender time limit{" "}
                <span className="mono">
                  {incident.senderTimeoutMs.toLocaleString()} ms
                </span>
                <span className="separator">/</span> Receiving-side records
              </p>
            </div>
            <button
              className="secondary shrink-0"
              onClick={() => {
                download(
                  "payload-clinic-report.md",
                  report(incident),
                  "text/markdown",
                );
                setNotice(
                  "Redacted report exported. Signature inputs were excluded.",
                );
              }}
            >
              <ArrowDownIcon /> Export report
            </button>
          </div>
          <div className="tabs" role="tablist" aria-label="Investigation views">
            {(["evidence", "compare", "signature"] as const).map((t) => (
              <button
                key={t}
                role="tab"
                aria-selected={tab === t}
                aria-controls={`panel-${t}`}
                id={`tab-${t}`}
                onClick={() => setTab(t)}
              >
                {t === "evidence"
                  ? "Delivery evidence"
                  : t === "compare"
                    ? "Compare attempts"
                    : "Signature check"}
              </button>
            ))}
          </div>
          <div className="toast-slot" aria-live="polite">
            {notice && (
              <p className="help flex items-center gap-2">
                <CheckIcon />
                {notice}
              </p>
            )}
          </div>
          <div
            role="tabpanel"
            id={`panel-${tab}`}
            aria-labelledby={`tab-${tab}`}
          >
            {tab === "evidence" && (
              <>
                <section className="evidence-overview">
                  <div>
                    <span className="eyebrow">Selected delivery</span>
                    <h3 className="mt-2">{current.id}</h3>
                    <p className="mono muted mt-1 text-sm">
                      {current.receivedAt}
                    </p>
                  </div>
                  <div className="reading">
                    <span className="eyebrow">HTTP status</span>
                    <strong className="mono">
                      {responseStatus(current.status)}
                    </strong>
                  </div>
                  <div className="reading">
                    <span className="eyebrow">Response duration</span>
                    <strong className="mono">
                      {current.durationMs.toLocaleString()}
                      <small> ms</small>
                    </strong>
                  </div>
                </section>
                <section aria-labelledby="findings-title" className="findings">
                  <div className="section-title">
                    <h3 id="findings-title">What the record says</h3>
                  </div>
                  {findings(incident, current).map((f, i) => (
                    <div className="finding" key={i}>
                      <span className={`finding-label ${f.kind}`}>
                        {f.kind === "observed" ? "Observed" : "Next check"}
                      </span>
                      <div>
                        <h4>{f.title}</h4>
                        <p className="muted mt-1">{f.detail}</p>
                      </div>
                    </div>
                  ))}
                </section>
                <div className="payload-grid">
                  <section>
                    <div className="section-title">
                      <h3>Request body</h3>
                      <span className="eyebrow">Redacted</span>
                    </div>
                    <pre tabIndex={0} aria-label="Redacted request body">
                      {current.requestBody}
                    </pre>
                  </section>
                  <section>
                    <div className="section-title">
                      <h3>Response body</h3>
                      <span className="eyebrow">Redacted</span>
                    </div>
                    <pre tabIndex={0} aria-label="Redacted response body">
                      {current.responseBody || "(empty response body)"}
                    </pre>
                  </section>
                </div>
                <details className="details">
                  <summary>
                    Headers and redaction log{" "}
                    <span className="mono">{incident.redactions.length}</span>
                  </summary>
                  <h4 className="mt-5 mb-2">Selected headers</h4>
                  <pre>{JSON.stringify(current.headers, null, 2)}</pre>
                  <h4 className="mt-5 mb-2">Removed before saving</h4>
                  {incident.redactions.length ? (
                    <ul className="redaction-list">
                      {incident.redactions.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="help">
                      No recognised secret fields or email patterns were found.
                    </p>
                  )}
                </details>
              </>
            )}
            {tab === "compare" && (
              <section className="space-y-6">
                <div className="section-title">
                  <div>
                    <h3>Compare two receiving-side records</h3>
                    <p className="muted mt-1">
                      Select the first attempt in the timeline, then choose a
                      second.
                    </p>
                  </div>
                </div>
                <label className="field max-w-md">
                  Second attempt
                  <select
                    value={compare}
                    onChange={(e) => setCompare(Number(e.target.value))}
                  >
                    {incident.attempts.map((a, i) => (
                      <option key={a.id} value={i}>
                        Attempt {i + 1}: {a.id} · {responseStatus(a.status)}
                      </option>
                    ))}
                  </select>
                </label>
                <dl className="comparison-summary">
                  <div>
                    <dt>Recorded gap, second minus first</dt>
                    <dd className="mono">{formatGap(differences.gapMs)}</dd>
                  </div>
                  <div>
                    <dt>Event identifier</dt>
                    <dd>
                      {differences.sameEvent
                        ? "Same event identifier"
                        : "Different event identifiers"}
                    </dd>
                  </div>
                  <div>
                    <dt>Redacted body</dt>
                    <dd>
                      {differences.sameBody
                        ? "Identical after redaction"
                        : "Different after redaction"}
                    </dd>
                  </div>
                  <div>
                    <dt>HTTP status</dt>
                    <dd className="mono">{differences.status}</dd>
                  </div>
                </dl>
                <div className="payload-grid">
                  <section>
                    <h4 className="mb-3">{current.id}</h4>
                    <pre tabIndex={0}>{current.requestBody}</pre>
                  </section>
                  <section>
                    <h4 className="mb-3">{other.id}</h4>
                    <pre tabIndex={0}>{other.requestBody}</pre>
                  </section>
                </div>
              </section>
            )}
            {tab === "signature" && <SignaturePanel />}
          </div>
          <footer className="page-foot">
            <FileTextIcon />
            <p>
              Use synthetic or already redacted records. Automatic redaction
              checks known patterns; review the log and content before sharing.
              Signing inputs clear when you leave their view.
            </p>
          </footer>
        </main>
      </div>
      {importing && (
        <div className="modal-backdrop">
          <section
            ref={modalRef}
            className="import-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="import-title"
          >
            <div className="section-title">
              <h2 id="import-title">Import a delivery record</h2>
              <button
                className="quiet"
                onClick={() => {
                  setImporting(false);
                  setInput("");
                  setError("");
                }}
              >
                Close
              </button>
            </div>
            <p className="muted mb-5">
              Choose a JSON incident file or paste one below. The importer
              validates the structure and redacts recognised secrets before
              saving anything.
            </p>
            <label className="field">
              JSON file
              <input
                type="file"
                accept="application/json,.json"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  if (file.size > 1_000_000) {
                    setError("Choose a file smaller than 1 MB.");
                    return;
                  }
                  load(await file.text());
                }}
              />
            </label>
            <label className="field mt-5">
              Or paste an incident
              <textarea
                rows={9}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                spellCheck={false}
              />
            </label>
            {error && (
              <p role="alert" className="error mt-3">
                {error}
              </p>
            )}
            <div className="flex flex-wrap gap-2 mt-5">
              <button className="primary" onClick={() => load(input)}>
                Validate and import
              </button>
              <button
                className="secondary"
                onClick={() =>
                  download(
                    "synthetic-webhook-incident.json",
                    sampleText,
                    "application/json",
                  )
                }
              >
                Download sample format
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
