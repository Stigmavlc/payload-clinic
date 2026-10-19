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
const email =
  /(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Z0-9-]{1,63}(?:\.[A-Z0-9-]{1,63})+(?![A-Z0-9-])/gi;
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
  if (
    !options.restoreRedactions &&
    new TextEncoder().encode(text).length > 1_000_000
  )
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
    (!options.restoreRedactions && input.title.length > 180)
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
  // A shared trie finds repeated values in one scan of each text field.
  const nodes: {
    edges: Map<string, number>;
    fail: number;
    lengths: number[];
  }[] = [{ edges: new Map(), fail: 0, lengths: [] }];
  for (const secret of knownSecrets) {
    let state = 0;
    for (const char of secret.split("")) {
      let next = nodes[state].edges.get(char);
      if (next === undefined) {
        next = nodes.length;
        nodes[state].edges.set(char, next);
        nodes.push({ edges: new Map(), fail: 0, lengths: [] });
      }
      state = next;
    }
    nodes[state].lengths.push(secret.length);
  }
  const queue = [...nodes[0].edges.values()];
  for (let index = 0; index < queue.length; index++) {
    const state = queue[index];
    for (const [char, child] of nodes[state].edges) {
      let fallback = nodes[state].fail;
      while (fallback && !nodes[fallback].edges.has(char))
        fallback = nodes[fallback].fail;
      nodes[child].fail = nodes[fallback].edges.get(char) ?? 0;
      nodes[child].lengths.push(...nodes[nodes[child].fail].lengths);
      queue.push(child);
    }
  }
  const repeated = (text: string, path: string): string => {
    if (!knownSecrets.size) return text;
    const ends = new Map<number, number>();
    let state = 0;
    for (let index = 0; index < text.length; index++) {
      const char = text[index];
      while (state && !nodes[state].edges.has(char)) state = nodes[state].fail;
      state = nodes[state].edges.get(char) ?? 0;
      for (const length of nodes[state].lengths) {
        const start = index + 1 - length;
        if (
          /[A-Za-z0-9_-]/.test(text[start - 1] ?? "") ||
          /[A-Za-z0-9_-]/.test(text[index + 1] ?? "")
        )
          continue;
        ends.set(start, Math.max(ends.get(start) ?? 0, index + 1));
      }
    }
    if (!ends.size) return text;
    const pieces: string[] = [];
    let cursor = 0;
    for (const [start, end] of [...ends].sort((a, b) => a[0] - b[0])) {
      if (start < cursor) continue;
      pieces.push(text.slice(cursor, start), "[secret removed]");
      cursor = end;
    }
    pieces.push(text.slice(cursor));
    redactions.add(`${path}: repeated secret`);
    return pieces.join("");
  };
  const scrubText = (value: string, path: string, repeat = true): string => {
    let clean = value.replace(email, () => {
      redactions.add(`${path}: email address`);
      return "[email removed]";
    });
    clean = clean.replace(
      authorizationText,
      (match, scheme: string, value: string) => {
        const candidate = value.replace(/\.+$/, "");
        const suffix = value.slice(candidate.length);
        let recognised =
          credentialLike(candidate) &&
          (/[0-9]/.test(candidate) ||
            (candidate.length >= 24 &&
              /[._~+/-]/.test(candidate) &&
              /[a-z]/.test(candidate) &&
              /[A-Z]/.test(candidate)));
        if (scheme.toLowerCase() === "basic") {
          try {
            recognised =
              candidate.length >= 12 &&
              /^[A-Za-z0-9+/]+={0,2}$/.test(candidate) &&
              atob(candidate).includes(":");
          } catch {
            recognised = false;
          }
        }
        if (!recognised) return match;
        redactions.add(`${path}: credential pattern`);
        return `${scheme} [credential removed]${suffix}`;
      },
    );
    clean = clean.replace(token, () => {
      redactions.add(`${path}: credential pattern`);
      return "[credential removed]";
    });
    return repeat ? repeated(clean, path) : clean;
  };
  const scrub = (value: unknown, path: string): unknown => {
    if (typeof value === "string") return scrubText(value, path);
    if (Array.isArray(value))
      return value.map((v, i) => scrub(v, `${path}[${i}]`));
    if (isRecord(value))
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => {
          if (sensitive.test(k)) {
            if (v !== "[removed]")
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
      JSON.parse(value);
    } catch {
      const fields = formFields(value);
      if (fields) {
        const clean = new URLSearchParams();
        fields.forEach((v, key) => {
          const safeKey = scrubText(key, path, false);
          if (sensitive.test(key)) {
            if (v !== "[removed]")
              redactions.add(`${path}.${safeKey}: sensitive form field`);
            clean.append(safeKey, "[removed]");
          } else clean.append(safeKey, scrubText(v, `${path}.${safeKey}`));
        });
        return clean.toString();
      }
      return scrubText(value, path);
    }
    // Patch only redacted tokens. Parsing and reserialising the whole body
    // would round large identifiers and change the recorded number spelling.
    const patches: { start: number; end: number; replacement: string }[] = [];
    let cursor = 0;
    const whitespace = () => {
      while (/\s/.test(value[cursor] ?? "") && cursor < value.length) cursor++;
    };
    const stringToken = () => {
      const start = cursor++;
      while (cursor < value.length) {
        const char = value[cursor++];
        if (char === "\\") cursor++;
        else if (char === '"') break;
      }
      return {
        start,
        end: cursor,
        decoded: JSON.parse(value.slice(start, cursor)) as string,
      };
    };
    const visit = (currentPath: string, apply: boolean, depth = 0): void => {
      if (depth > 40) throw new Error("The JSON sample is nested too deeply.");
      whitespace();
      const char = value[cursor];
      if (char === '"') {
        const item = stringToken();
        if (apply) {
          const clean = scrubText(item.decoded, currentPath);
          if (clean !== item.decoded)
            patches.push({ ...item, replacement: JSON.stringify(clean) });
        }
      } else if (char === "{") {
        cursor++;
        whitespace();
        while (value[cursor] !== "}") {
          const key = stringToken();
          const safeKey = apply
            ? scrubText(key.decoded, currentPath, false)
            : key.decoded;
          if (apply && safeKey !== key.decoded)
            patches.push({ ...key, replacement: JSON.stringify(safeKey) });
          whitespace();
          cursor++; // colon, already checked by JSON.parse
          whitespace();
          const start = cursor;
          const remove = apply && sensitive.test(key.decoded);
          visit(`${currentPath}.${safeKey}`, apply && !remove, depth + 1);
          if (remove) {
            if (value.slice(start, cursor) !== '"[removed]"')
              redactions.add(`${currentPath}.${safeKey}: sensitive field`);
            patches.push({ start, end: cursor, replacement: '"[removed]"' });
          }
          whitespace();
          if (value[cursor] !== ",") break;
          cursor++;
          whitespace();
        }
        cursor++;
      } else if (char === "[") {
        cursor++;
        whitespace();
        let index = 0;
        while (value[cursor] !== "]") {
          visit(`${currentPath}[${index++}]`, apply, depth + 1);
          whitespace();
          if (value[cursor] !== ",") break;
          cursor++;
        }
        cursor++;
      } else {
        while (cursor < value.length && !/[\s,}\]]/.test(value[cursor]))
          cursor++;
      }
    };
    visit(path, true);
    const pieces: string[] = [];
    let previous = 0;
    for (const patch of patches.sort((a, b) => a.start - b.start)) {
      pieces.push(value.slice(previous, patch.start), patch.replacement);
      previous = patch.end;
    }
    pieces.push(value.slice(previous));
    return pieces.join("");
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
  if (new Set(attempts.map((a) => a.id)).size !== attempts.length)
    throw new Error(
      "Attempt identifiers become identical after redaction. Give them unique non-sensitive labels before importing.",
    );
  const title = scrubText(input.title, "title");
  const restoredLog: string[] = [];
  if (options.restoreRedactions && Array.isArray(input.redactions))
    for (const entry of input.redactions)
      if (typeof entry === "string")
        restoredLog.push(scrubText(entry, "saved redaction log"));
  return {
    title,
    senderTimeoutMs: input.senderTimeoutMs,
    attempts,
    redactions: [...new Set([...restoredLog, ...redactions])],
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
