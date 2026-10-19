export type Attempt = {
  id: string;
  eventId: string;
  receivedAt: string;
  status: number | null;
  durationMs: number;
  headers: Record<string, string>;
  requestBody: string;
  responseBody: string;
};
export type Incident = {
  title: string;
  senderTimeoutMs: number;
  attempts: Attempt[];
  redactions: string[];
};
export type Finding = {
  kind: "observed" | "check";
  title: string;
  detail: string;
};
const sensitive =
  /authorization|cookie|signature|token|secret|password|api.?key|email/i;
const email = /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/gi;
const token =
  /\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]+|whsec_[A-Za-z0-9]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/gi;
const authorizationText = /\b(Bearer|Basic)\s+([A-Za-z0-9._~+/-]+={0,2})/gi;
const credentialLike = (value: string): boolean =>
  value.length >= 12 &&
  !/\s/.test(value) &&
  (/[0-9_+/=.-]/.test(value) || /^[a-f0-9]{32,}$/i.test(value));
const isRecord = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);

/** Validate documented fields and redact recognised patterns before storage. */
export function importIncident(
  text: string,
  options: { restoreRedactions?: boolean } = {},
): Incident {
  if (new TextEncoder().encode(text).length > 1_000_000)
    throw new Error(
      "The sample is larger than 1 MB. Import a smaller, redacted incident.",
    );
  let input: unknown;
  try {
    input = JSON.parse(text);
  } catch {
    throw new Error(
      "This file is not valid JSON. Check commas, quotes and the closing brackets.",
    );
  }
  if (
    !isRecord(input) ||
    typeof input.title !== "string" ||
    !input.title.trim() ||
    input.title.length > 180
  )
    throw new Error("Provide a title of 1 to 180 characters.");
  if (
    typeof input.senderTimeoutMs !== "number" ||
    !Number.isFinite(input.senderTimeoutMs) ||
    input.senderTimeoutMs <= 0
  )
    throw new Error(
      "senderTimeoutMs must be a positive number supplied by the sender.",
    );
  if (
    !Array.isArray(input.attempts) ||
    input.attempts.length < 1 ||
    input.attempts.length > 100
  )
    throw new Error("Provide between 1 and 100 delivery attempts.");
  const rawAttempts: Attempt[] = input.attempts.map((a, i) => {
    const prefix = `Attempt ${i + 1}`;
    if (!isRecord(a)) throw new Error(`${prefix} must be an object.`);
    for (const key of [
      "id",
      "eventId",
      "receivedAt",
      "requestBody",
      "responseBody",
    ]) {
      if (typeof a[key] !== "string")
        throw new Error(`${prefix}: ${key} must be a string.`);
    }
    if (!(a.id as string).trim() || !(a.eventId as string).trim())
      throw new Error(`${prefix}: identifiers cannot be empty.`);
    if (
      !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(
        a.receivedAt as string,
      ) ||
      !Number.isFinite(Date.parse(a.receivedAt as string))
    )
      throw new Error(
        `${prefix}: receivedAt needs a valid ISO timestamp with a time zone.`,
      );
    if (
      a.status !== null &&
      (typeof a.status !== "number" ||
        !Number.isInteger(a.status) ||
        a.status < 100 ||
        a.status > 599)
    )
      throw new Error(
        `${prefix}: status must be an HTTP status from 100 to 599, or null when no response was recorded.`,
      );
    if (
      typeof a.durationMs !== "number" ||
      !Number.isFinite(a.durationMs) ||
      a.durationMs < 0
    )
      throw new Error(`${prefix}: durationMs must be a non-negative number.`);
    if (
      !isRecord(a.headers) ||
      Object.values(a.headers).some((v) => typeof v !== "string")
    )
      throw new Error(`${prefix}: headers must map names to strings.`);
    return {
      id: a.id as string,
      eventId: a.eventId as string,
      receivedAt: a.receivedAt as string,
      status: a.status as number | null,
      durationMs: a.durationMs,
      headers: a.headers as Record<string, string>,
      requestBody: a.requestBody as string,
      responseBody: a.responseBody as string,
    };
  });
  if (new Set(rawAttempts.map((a) => a.id)).size !== rawAttempts.length)
    throw new Error(
      "Each attempt id must be unique. Repeated eventId values are allowed.",
    );

  const redactions = new Set<string>();
  const knownSecrets = new Set<string>();
  const remember = (value: string) => {
    if (credentialLike(value)) knownSecrets.add(value);
  };
  const formFields = (value: string): URLSearchParams | null =>
    /^[^=&\s]+=[^\r\n]*$/.test(value) ? new URLSearchParams(value) : null;
  const collect = (value: unknown, path: string, depth = 0): void => {
    if (depth > 40) throw new Error("The JSON sample is nested too deeply.");
    if (Array.isArray(value))
      return value.forEach((v, i) => collect(v, `${path}[${i}]`, depth + 1));
    if (isRecord(value))
      for (const [key, v] of Object.entries(value)) {
        if (sensitive.test(key) && typeof v === "string") {
          remember(v);
          if (/authorization/i.test(key)) {
            const credential = /^(?:Bearer|Basic)\s+(\S+)$/i.exec(v);
            if (credential) remember(credential[1]);
          }
          if (/signature/i.test(key)) {
            for (const match of v.matchAll(
              /(?:^|,)\s*v1=([a-fA-F0-9]{64})(?=,|$)/g,
            ))
              remember(match[1]);
          }
        }
        collect(v, `${path}.${key}`, depth + 1);
      }
  };
  collect(input, "incident");
  for (const a of rawAttempts)
    for (const body of [a.requestBody, a.responseBody]) {
      try {
        collect(JSON.parse(body), a.id);
      } catch (e) {
        if (e instanceof Error && e.message.includes("nested too deeply"))
          throw e;
        formFields(body)?.forEach((v, key) => {
          if (sensitive.test(key)) remember(v);
        });
      }
    }
  const scrubText = (value: string, path: string, repeat = true): string => {
    let clean = value.replace(email, () => {
      redactions.add(`${path}: email address`);
      return "[email removed]";
    });
    clean = clean.replace(
      authorizationText,
      (match, scheme: string, value: string) => {
        let recognised = credentialLike(value);
        if (scheme.toLowerCase() === "basic") {
          try {
            recognised =
              value.length >= 12 &&
              /^[A-Za-z0-9+/]+={0,2}$/.test(value) &&
              atob(value).includes(":");
          } catch {
            recognised = false;
          }
        }
        if (!recognised) return match;
        redactions.add(`${path}: credential pattern`);
        return `${scheme} [credential removed]`;
      },
    );
    clean = clean.replace(token, () => {
      redactions.add(`${path}: credential pattern`);
      return "[credential removed]";
    });
    for (const secret of [...knownSecrets].sort(
      (a, b) => b.length - a.length,
    )) {
      if (!repeat) continue;
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const match = new RegExp(
        `(?<![A-Za-z0-9_-])${escaped}(?![A-Za-z0-9_-])`,
        "g",
      );
      clean = clean.replace(match, () => {
        redactions.add(`${path}: repeated secret`);
        return "[secret removed]";
      });
    }
    return clean;
  };
  const scrub = (value: unknown, path: string): unknown => {
    if (typeof value === "string") return scrubText(value, path);
    if (Array.isArray(value))
      return value.map((v, i) => scrub(v, `${path}[${i}]`));
    if (isRecord(value))
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => {
          if (sensitive.test(k)) {
            redactions.add(
              `${path}.${scrubText(k, path, false)}: sensitive field`,
            );
            return [scrubText(k, path, false), "[removed]"];
          }
          return [
            scrubText(k, path, false),
            scrub(v, `${path}.${scrubText(k, "field name", false)}`),
          ];
        }),
      );
    return value;
  };
  const body = (value: string, path: string): string => {
    try {
      return JSON.stringify(scrub(JSON.parse(value), path), null, 2);
    } catch {
      const fields = formFields(value);
      if (fields) {
        const clean = new URLSearchParams();
        fields.forEach((v, key) => {
          const safeKey = scrubText(key, path, false);
          if (sensitive.test(key)) {
            redactions.add(`${path}.${safeKey}: sensitive form field`);
            clean.append(safeKey, "[removed]");
          } else clean.append(safeKey, scrubText(v, `${path}.${safeKey}`));
        });
        return clean.toString();
      }
      return scrubText(value, path);
    }
  };
  const attempts = rawAttempts
    .map((a, i) => ({
      ...a,
      id: scrubText(a.id, `attempt ${i + 1}.id`),
      eventId: scrubText(a.eventId, `attempt ${i + 1}.eventId`),
      headers: scrub(a.headers, `attempt ${i + 1}.headers`) as Record<
        string,
        string
      >,
      requestBody: body(a.requestBody, `attempt ${i + 1}.requestBody`),
      responseBody: body(a.responseBody, `attempt ${i + 1}.responseBody`),
    }))
    .sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt));
  if (options.restoreRedactions && Array.isArray(input.redactions)) {
    for (const entry of input.redactions.slice(0, 10000)) {
      if (typeof entry === "string" && entry.length <= 1000)
        redactions.add(scrubText(entry, "saved redaction log"));
    }
  }
  return {
    title: scrubText(input.title, "title"),
    senderTimeoutMs: input.senderTimeoutMs,
    attempts,
    redactions: [...redactions],
  };
}

export function findings(incident: Incident, attempt: Attempt): Finding[] {
  const result: Finding[] = [];
  const status = attempt.status;
  if (status === null)
    result.push({
      kind: "observed",
      title: "No HTTP response recorded",
      detail:
        "This sample alone cannot distinguish a connection failure from an unrecorded response.",
    });
  else if (status >= 200 && status < 300)
    result.push({
      kind: "observed",
      title: `Receiver returned ${status}`,
      detail:
        "The receiving endpoint accepted this delivery at HTTP level. This does not establish that downstream processing completed.",
    });
  else if (status >= 400 && status < 500)
    result.push({
      kind: "observed",
      title: `Receiver returned ${status}`,
      detail:
        "The endpoint returned a client error. Inspect the response body and request contract before deciding why.",
    });
  else if (status >= 500)
    result.push({
      kind: "observed",
      title: `Receiver returned ${status}`,
      detail:
        "The endpoint returned a server error. Receiver logs are needed to establish its cause.",
    });
  else
    result.push({
      kind: "observed",
      title: `Receiver returned ${status}`,
      detail:
        status >= 300
          ? "A redirect is not proof of successful webhook delivery. Check the sender’s redirect policy."
          : "An informational response alone does not confirm a completed delivery.",
    });
  if (attempt.durationMs >= incident.senderTimeoutMs)
    result.push({
      kind: "check",
      title: "Response reached the sender’s time limit",
      detail: `${attempt.durationMs} ms was recorded against a ${incident.senderTimeoutMs} ms limit. The receiver may have processed an event even if the sender timed out. Check both records before replaying it.`,
    });
  try {
    JSON.parse(attempt.requestBody);
  } catch {
    result.push({
      kind: "observed",
      title: "Request body is not valid JSON",
      detail:
        "This is only an error if the endpoint contract requires JSON. Inspect the expected content type and original bytes.",
    });
  }
  const sameEvent = incident.attempts.filter(
    (a) => a.eventId === attempt.eventId,
  );
  if (sameEvent.length > 1)
    result.push({
      kind: "observed",
      title: "Event identifier repeated",
      detail: `${sameEvent.length} attempts share this event identifier. A retry is a possible explanation; confirm the sender’s record and the receiver’s idempotency handling.`,
    });
  if (sameEvent.some((a) => a.requestBody !== attempt.requestBody))
    result.push({
      kind: "check",
      title: "Payload differs for the same event",
      detail:
        "The redacted request bodies differ. Compare attempts and inspect the source records; redaction can also hide differences.",
    });
  return result;
}

export function compareAttempts(left: Attempt, right: Attempt) {
  return {
    gapMs: Date.parse(right.receivedAt) - Date.parse(left.receivedAt),
    sameEvent: left.eventId === right.eventId,
    sameBody: left.requestBody === right.requestBody,
    status: `${left.status ?? "none"} → ${right.status ?? "none"}`,
    durationChangeMs: right.durationMs - left.durationMs,
  };
}

export function report(incident: Incident): string {
  const fenced = (body: string): string => {
    const length = Math.max(
      3,
      ...[...body.matchAll(/`+/g)].map((match) => match[0].length + 1),
    );
    const fence = "`".repeat(length);
    let language = "text";
    try {
      JSON.parse(body);
      language = "json";
    } catch {
      /* Keep the recorded text. */
    }
    return `${fence}${language}\n${body}\n${fence}`;
  };
  return [
    `# ${incident.title}`,
    "",
    "Redacted investigation sample. Observations do not establish root cause. No live requests were made.",
    "",
    `Sender time limit: ${incident.senderTimeoutMs} ms`,
    "",
    ...incident.attempts.flatMap((a) => [
      `## ${a.id}`,
      `Event: ${a.eventId}`,
      `Received: ${a.receivedAt}`,
      `Status: ${a.status ?? "not recorded"}; duration: ${a.durationMs} ms`,
      ...findings(incident, a).map(
        (f) =>
          `${f.kind === "observed" ? "Observed" : "Check"}: ${f.title}. ${f.detail}`,
      ),
      "",
      "Request:",
      fenced(a.requestBody),
      "",
      "Response:",
      fenced(a.responseBody),
      "",
    ]),
    "## Redactions",
    ...incident.redactions.map((x) => `- ${x}`),
    "",
    "Signature checker inputs are excluded. Recognised patterns were removed; review the report content before sharing.",
  ].join("\n");
}
