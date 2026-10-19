import * as jsonc from "jsonc-parser";
import { createScanner, getNodePath, parseTree, type Node } from "jsonc-parser";
const tokenKinds = (jsonc as unknown as { SyntaxKind: Record<string, number> })
  .SyntaxKind;
export type BodyCheck =
  "json" | "form" | "json-like" | "text" | "empty" | "unknown";
export type Attempt = {
  id: string;
  eventId: string;
  receivedAt: string;
  status: number | null;
  durationMs: number;
  headers: Record<string, string>;
  requestBody: string;
  responseBody: string;
  requestChecks?: BodyCheck;
  responseChecks?: BodyCheck;
};
export type Incident = {
  title: string;
  senderTimeoutMs: number;
  attempts: Attempt[];
  redactions: string[];
  example?: "booking" | "inventory";
};
export type Finding = {
  kind: "observed" | "check";
  title: string;
  detail: string;
};
const sensitive =
  /authorization|cookie|signature|token|secret|password|api.?key|email/i;
const signatureField = (key: string): boolean => {
  const words = key.replace(/([a-z0-9])([A-Z])/g, "$1-$2");
  return (
    /signature/i.test(words) ||
    /(?:^|[-_.\s])(?:hmac(?:sha[0-9]+)?|sig(?:[0-9]+)?)(?:$|[-_.\s])/i.test(
      words,
    )
  );
};
const sensitiveField = (key: string): boolean => {
  const original = key.replace(/\[(?:email|secret|credential) removed\]/gi, "");
  return sensitive.test(original) || signatureField(original);
};
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

const formFields = (value: string): URLSearchParams | null => {
  const text = value.trim();
  return !/^[{"]/.test(text) &&
    text.includes("=") &&
    /^[^&=\s]+(?:=[^\r\n&]*)?(?:&[^&=\s]+(?:=[^\r\n&]*)?)*$/.test(text)
    ? new URLSearchParams(text)
    : null;
};
const looksLikeJSON = (value: string) => /^\s*(?:[\[{]|\/[/\*])/.test(value);
export function bodyCheckKind(value: string): BodyCheck {
  if (!value) return "empty";
  try {
    JSON.parse(value);
    return "json";
  } catch {
    /* Keep the source bytes. */
  }
  if (formFields(value)) return "form";
  if (looksLikeJSON(value) && looseFields(value).length) return "json-like";
  return "text";
}
export function bodyChecks(
  value: string,
  checks = bodyCheckKind(value),
): string {
  switch (checks) {
    case "empty":
      return "No body recorded.";
    case "json":
      return "JSON fields and text patterns checked.";
    case "form":
      return "Form fields and text patterns checked.";
    case "json-like":
      return "JSON-like fields and text patterns checked. Recorded JSON is invalid.";
    case "unknown":
      return "Original check scope was not saved; review this saved body before sharing.";
    default:
      return "Text patterns only; this body has no JSON or form field checks.";
  }
}
function restoredScope(value: unknown): BodyCheck {
  return typeof value === "string" &&
    ["json", "form", "json-like", "text", "empty", "unknown"].includes(value)
    ? (value as BodyCheck)
    : "unknown";
}
type LooseField = {
  key: string;
  path: (string | number)[];
  start: number;
  end: number;
  node?: Node;
};
function recoveredRecordStarts(value: string): number[] {
  const scanner = createScanner(value, true);
  const starts: number[] = [];
  const stack: number[] = [];
  let previous: number | undefined;
  let previousEnd = 0;
  let kind: number;
  while ((kind = scanner.scan()) !== tokenKinds.EOF) {
    const offset = scanner.getTokenOffset();
    const opens =
      kind === tokenKinds.OpenBraceToken ||
      kind === tokenKinds.OpenBracketToken;
    if (opens) {
      const acceptsValue =
        previous === tokenKinds.ColonToken ||
        previous === tokenKinds.OpenBracketToken ||
        (previous === tokenKinds.CommaToken &&
          stack.at(-1) === tokenKinds.OpenBracketToken);
      const beginsLine = /[\r\n]/.test(value.slice(previousEnd, offset));
      if (!stack.length || (beginsLine && !acceptsValue)) {
        starts.push(offset);
        stack.length = 0;
      }
      stack.push(kind);
    } else if (
      kind === tokenKinds.CloseBraceToken ||
      kind === tokenKinds.CloseBracketToken
    ) {
      stack.pop();
    }
    previous = kind;
    previousEnd = offset + scanner.getTokenLength();
  }
  return starts;
}
function looseFields(value: string): LooseField[] {
  const fields: LooseField[] = [];
  let records = 0;
  const starts = recoveredRecordStarts(value);
  for (let index = 0; index < starts.length; index++) {
    let base = starts[index];
    const limit = starts[index + 1] ?? value.length;
    while (base < limit) {
      const scanner = createScanner(value.slice(0, limit), true);
      scanner.setPosition(base);
      let kind = scanner.scan();
      while (
        ![
          tokenKinds.OpenBraceToken,
          tokenKinds.OpenBracketToken,
          tokenKinds.EOF,
        ].includes(kind)
      )
        kind = scanner.scan();
      if (kind === tokenKinds.EOF) break;
      base = scanner.getTokenOffset();
      const record = records++;
      const tree = parseTree(value.slice(base, limit), [], {
        allowTrailingComma: true,
      });
      if (!tree) {
        base++;
        continue;
      }
      const walk = (node: Node, depth = 0): void => {
        if (depth > 40)
          throw new Error("The JSON sample is nested too deeply.");
        if (
          node.type === "property" &&
          node.children?.[0] &&
          typeof node.colonOffset === "number"
        ) {
          const child = node.children[1];
          let start = child?.offset ?? node.colonOffset + 1;
          let end = child ? child.offset + child.length : start;
          if (!child) {
            const scanner = createScanner(value.slice(base, limit), true);
            scanner.setPosition(start);
            const token = scanner.scan();
            start = scanner.getTokenOffset();
            if (
              ![
                tokenKinds.CloseBraceToken,
                tokenKinds.CloseBracketToken,
                tokenKinds.CommaToken,
                tokenKinds.EOF,
              ].includes(token)
            ) {
              end = start;
              if (value[base + start] === "'") {
                end++;
                while (base + end < limit) {
                  const character = value[base + end++];
                  if (character === "\\") end++;
                  else if (character === "'") break;
                }
              } else {
                while (
                  base + end < limit &&
                  !/[,}\]]/.test(value[base + end])
                ) {
                  if (
                    value[base + end] === "/" &&
                    /[/*]/.test(value[base + end + 1] ?? "")
                  )
                    break;
                  end++;
                }
                while (end > start && /\s/.test(value[base + end - 1])) end--;
              }
            } else end = start;
          }
          fields.push({
            key: node.children[0].value as string,
            path: [
              record,
              ...getNodePath(node.children[0])
                .slice(0, -1)
                .concat(node.children[0].value),
            ],
            start: base + start,
            end: base + end,
            node: child,
          });
        }
        node.children?.forEach((child) => walk(child, depth + 1));
      };
      walk(tree);
      const next = base + tree.offset + tree.length;
      if (next <= base) break;
      base = next;
    }
  }
  if (records === 1) fields.forEach((field) => field.path.shift());
  return fields.sort((a, b) => a.start - b.start || b.end - a.end);
}
const emptyLooseField = (field: LooseField, value: string): boolean => {
  const node = field.node;
  const recorded = value.slice(field.start, field.end);
  if (["null", "true", "false", '\"\"'].includes(recorded)) return true;
  if (
    node &&
    (node.type === "array" || node.type === "object") &&
    !node.children?.length
  ) {
    const scanner = createScanner(recorded, true);
    const opening = scanner.scan(),
      closing = scanner.scan(),
      end = scanner.scan();
    return (
      end === tokenKinds.EOF &&
      ((opening === tokenKinds.OpenBraceToken &&
        closing === tokenKinds.CloseBraceToken) ||
        (opening === tokenKinds.OpenBracketToken &&
          closing === tokenKinds.CloseBracketToken))
    );
  }
  return false;
};

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
      requestChecks: options.restoreRedactions
        ? restoredScope(a.requestChecks)
        : bodyCheckKind(a.requestBody as string),
      responseChecks: options.restoreRedactions
        ? restoredScope(a.responseChecks)
        : bodyCheckKind(a.responseBody as string),
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
  const collect = (value: unknown, path: string, depth = 0): void => {
    if (depth > 40) throw new Error("The JSON sample is nested too deeply.");
    if (Array.isArray(value))
      return value.forEach((v, i) => collect(v, `${path}[${i}]`, depth + 1));
    if (isRecord(value))
      for (const [key, v] of Object.entries(value)) {
        if (sensitiveField(key) && typeof v === "string") {
          remember(v);
          if (/authorization/i.test(key)) {
            const credential = /^(?:Bearer|Basic)\s+(\S+)$/i.exec(v);
            if (credential) remember(credential[1]);
          }
          if (signatureField(key)) {
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
          if (sensitiveField(key)) remember(v);
        });
        if (looksLikeJSON(body))
          for (const field of looseFields(body)) {
            if (sensitiveField(field.key) && !emptyLooseField(field, body)) {
              if (typeof field.node?.value === "string")
                remember(field.node.value);
              else {
                const recorded = body.slice(field.start, field.end).trim();
                remember(recorded);
                if (recorded.startsWith("'") && recorded.endsWith("'"))
                  remember(recorded.slice(1, -1).replace(/\\(['\\])/g, "$1"));
              }
            }
          }
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
  const fieldNames = () => ({
    aliases: new Map<string, string>(),
    used: new Set<string>(),
  });
  const fieldName = (
    key: string,
    path: string,
    names: ReturnType<typeof fieldNames>,
  ): string => {
    const existing = names.aliases.get(key);
    if (existing !== undefined) return existing;
    const base = scrubText(key, `${path}.field name`, false);
    let safe = base;
    for (let number = 2; names.used.has(safe); number++)
      safe = `${base} [${number}]`;
    names.used.add(safe);
    names.aliases.set(key, safe);
    return safe;
  };
  const scrub = (value: unknown, path: string): unknown => {
    if (typeof value === "string") return scrubText(value, path);
    if (Array.isArray(value))
      return value.map((v, i) => scrub(v, `${path}[${i}]`));
    if (isRecord(value)) {
      const used = fieldNames();
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => {
          const safeKey = fieldName(k, path, used);
          if (
            sensitiveField(k) &&
            v !== null &&
            typeof v !== "boolean" &&
            v !== "" &&
            v !== "true" &&
            v !== "false" &&
            !(Array.isArray(v) && v.length === 0) &&
            !(isRecord(v) && Object.keys(v).length === 0)
          ) {
            if (v !== "[removed]")
              redactions.add(`${path}.${safeKey}: sensitive field`);
            return [safeKey, "[removed]"];
          }
          return [safeKey, scrub(v, `${path}.${safeKey}`)];
        }),
      );
    }
    return value;
  };
  const body = (value: string, path: string): string => {
    try {
      JSON.parse(value);
    } catch {
      if (looksLikeJSON(value) && !formFields(value)) {
        const patches = looseFields(value).filter(
          (field) =>
            sensitiveField(field.key) &&
            field.end > field.start &&
            !emptyLooseField(field, value),
        );
        const pieces: string[] = [];
        let cursor = 0;
        for (const field of patches) {
          if (field.start < cursor) continue;
          pieces.push(scrubText(value.slice(cursor, field.start), path));
          pieces.push("[removed]");
          const safePath = scrubText(
            field.path
              .map((part) =>
                typeof part === "number" ? `[${part}]` : `.${part}`,
              )
              .join(""),
            path,
          );
          if (
            !["[removed]", '"[removed]"'].includes(
              value.slice(field.start, field.end),
            )
          )
            redactions.add(`${path}${safePath}: sensitive field`);
          cursor = field.end;
        }
        pieces.push(scrubText(value.slice(cursor), path));
        return pieces.join("");
      }
      const fields = formFields(value);
      if (fields) {
        const readableEncoding = (text: string) =>
          encodeURIComponent(text)
            .replace(/%5B/gi, "[")
            .replace(/%5D/gi, "]")
            .replace(/%20/g, " ");
        const names = new Map<string, string>();
        const used = fieldNames();
        const leading = /^\s*/.exec(value)![0];
        const trailing = /\s*$/.exec(value)![0];
        const content = value.slice(
          leading.length,
          value.length - trailing.length,
        );
        return (
          leading +
          content
            .split("&")
            .map((part) => {
              const entry = [...new URLSearchParams(part)][0];
              if (!entry) return part;
              const [key, v] = entry;
              const separator = part.indexOf("=");
              const rawKey = separator < 0 ? part : part.slice(0, separator);
              const rawValue = separator < 0 ? "" : part.slice(separator + 1);
              const safeKey = names.get(key) ?? fieldName(key, path, used);
              names.set(key, safeKey);
              let safeValue: string;
              if (
                sensitiveField(key) &&
                v !== "" &&
                v !== "true" &&
                v !== "false"
              ) {
                if (v !== "[removed]")
                  redactions.add(`${path}.${safeKey}: sensitive form field`);
                safeValue = "[removed]";
              } else safeValue = scrubText(v, `${path}.${safeKey}`);
              if (safeKey === key && safeValue === v) return part;
              return (
                (safeKey === key ? rawKey : readableEncoding(safeKey)) +
                "=" +
                (safeValue === v ? rawValue : readableEncoding(safeValue))
              );
            })
            .join("&") +
          trailing
        );
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
        const used = fieldNames();
        cursor++;
        whitespace();
        while (value[cursor] !== "}") {
          const key = stringToken();
          const safeKey = apply
            ? fieldName(key.decoded, currentPath, used)
            : key.decoded;
          if (apply && safeKey !== key.decoded)
            patches.push({ ...key, replacement: JSON.stringify(safeKey) });
          whitespace();
          cursor++; // colon, already checked by JSON.parse
          whitespace();
          const start = cursor;
          const remove = apply && sensitiveField(key.decoded);
          visit(`${currentPath}.${safeKey}`, apply && !remove, depth + 1);
          const recorded = value.slice(start, cursor);
          const keepEmpty =
            ["null", "true", "false", '""'].includes(recorded) ||
            /^\[\s*\]$/.test(recorded) ||
            /^\{\s*\}$/.test(recorded);
          if (remove && !keepEmpty) {
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
  const orderedAttempts = [...rawAttempts].sort(
    (a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt),
  );
  const attempts = orderedAttempts.map((a, i) => ({
    ...a,
    id: scrubText(a.id, `attempt ${i + 1}.id`),
    eventId: scrubText(a.eventId, `attempt ${i + 1}.eventId`),
    headers: scrub(a.headers, `attempt ${i + 1}.headers`) as Record<
      string,
      string
    >,
    requestBody: body(a.requestBody, `attempt ${i + 1}.requestBody`),
    responseBody: body(a.responseBody, `attempt ${i + 1}.responseBody`),
  }));
  if (new Set(attempts.map((a) => a.id)).size !== attempts.length)
    throw new Error(
      "Attempt identifiers become identical after redaction. Give them unique non-sensitive labels before importing.",
    );
  const eventOrigins = new Map<string, string>();
  attempts.forEach((attempt, index) => {
    const original = orderedAttempts[index].eventId;
    const previous = eventOrigins.get(attempt.eventId);
    if (previous !== undefined && previous !== original)
      throw new Error(
        "Different event identifiers become identical after redaction. Replace them with distinct labels before importing, keeping genuinely repeated events labelled alike.",
      );
    eventOrigins.set(attempt.eventId, original);
  });
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
    ...(options.restoreRedactions &&
    (input.example === "booking" || input.example === "inventory")
      ? { example: input.example }
      : {}),
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
      detail: `${formatNumber(attempt.durationMs)} ms was recorded against a ${formatNumber(incident.senderTimeoutMs)} ms limit. The receiver may have processed an event even if the sender timed out. Check both records before replaying it.`,
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

export function formatNumber(value: number): string {
  return value.toLocaleString("en-GB", { maximumFractionDigits: 20 });
}

export function formatGap(milliseconds: number): string {
  let remaining = Math.abs(milliseconds);
  const parts: string[] = [];
  for (const [size, unit] of [
    [86400000, "day"],
    [3600000, "hour"],
    [60000, "minute"],
  ] as const) {
    const count = Math.floor(remaining / size);
    if (count)
      parts.push(`${formatNumber(count)} ${unit}${count === 1 ? "" : "s"}`);
    remaining %= size;
  }
  const seconds = Number((remaining / 1000).toFixed(3));
  if (seconds || !parts.length)
    parts.push(`${formatNumber(seconds)} second${seconds === 1 ? "" : "s"}`);
  return `${milliseconds < 0 ? "minus " : ""}${parts.join(", ")}`;
}

export function responseStatus(status: number | null): string {
  return status === null ? "No response recorded" : String(status);
}

export function compareAttempts(left: Attempt, right: Attempt) {
  return {
    gapMs: Date.parse(right.receivedAt) - Date.parse(left.receivedAt),
    sameEvent: left.eventId === right.eventId,
    sameBody: left.requestBody === right.requestBody,
    status: `${responseStatus(left.status)} → ${responseStatus(right.status)}`,
    durationChangeMs: right.durationMs - left.durationMs,
  };
}

export function report(incident: Incident): string {
  const fenced = (body: string, checks = bodyCheckKind(body)): string => {
    const length = Math.max(
      3,
      ...[...body.matchAll(/`+/g)].map((match) => match[0].length + 1),
    );
    const fence = "`".repeat(length);
    let language = "text";
    try {
      JSON.parse(body);
      if (checks === "json") language = "json";
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
    `Sender time limit: ${formatNumber(incident.senderTimeoutMs)} ms`,
    "",
    ...incident.attempts.flatMap((a, i) => [
      `## Attempt ${i + 1}: ${a.id}`,
      `Event: ${a.eventId}`,
      `Received: ${a.receivedAt}`,
      ...(i
        ? [
            `Gap from previous attempt: ${formatGap(Date.parse(a.receivedAt) - Date.parse(incident.attempts[i - 1].receivedAt))}`,
          ]
        : []),
      `Status: ${responseStatus(a.status)}; duration: ${formatNumber(a.durationMs)} ms`,
      ...findings(incident, a).map(
        (f) =>
          `${f.kind === "observed" ? "Observed" : "Check"}: ${f.title}. ${f.detail}`,
      ),
      "",
      "Headers:",
      Object.keys(a.headers).length
        ? fenced(JSON.stringify(a.headers, null, 2))
        : "No headers recorded",
      "",
      "Request:",
      bodyChecks(a.requestBody, a.requestChecks),
      fenced(a.requestBody, a.requestChecks),
      "",
      "Response:",
      bodyChecks(a.responseBody, a.responseChecks),
      fenced(a.responseBody || "(empty response body)", a.responseChecks),
      "",
    ]),
    "## Redactions",
    ...incident.redactions.map((x) => `- ${x}`),
    "",
    "Signature checker inputs are excluded. Recognised patterns were removed; review the report content before sharing.",
  ].join("\n");
}
