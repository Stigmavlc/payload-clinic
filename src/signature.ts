const encoder = new TextEncoder();
export async function hmacSha256(
  key: Uint8Array,
  text: string,
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const bytes = new Uint8Array(
    await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(text)),
  );
  return Array.from(bytes, (n) => n.toString(16).padStart(2, "0")).join("");
}
export async function verifyStripe(
  raw: string,
  header: string,
  secret: string,
  nowSeconds: number,
  toleranceSeconds = 300,
) {
  if (!secret) throw new Error("Enter the signing secret for this session.");
  const parts = header.split(",").map((p) => p.trim().split("="));
  const timestamps = parts.filter((p) => p[0] === "t");
  if (timestamps.length !== 1 || !/^\d+$/.test(timestamps[0][1] ?? ""))
    throw new Error("The header needs exactly one integer t timestamp.");
  const timestamp = Number(timestamps[0][1]);
  if (!Number.isSafeInteger(timestamp))
    throw new Error("The signature timestamp is outside the supported range.");
  const signatures = parts
    .filter((p) => p[0] === "v1")
    .map((p) => p[1])
    .filter((s) => /^[a-fA-F0-9]{64}$/.test(s ?? ""));
  if (!signatures.length)
    throw new Error(
      "The header needs a v1 SHA-256 signature with 64 hexadecimal characters.",
    );
  const digest = await hmacSha256(
    encoder.encode(secret),
    `${timestamp}.${raw}`,
  );
  const matches = signatures.some((s) => {
    let different = 0;
    const value = s.toLowerCase();
    for (let i = 0; i < digest.length; i++)
      different |= digest.charCodeAt(i) ^ value.charCodeAt(i);
    return different === 0;
  });
  return {
    matches,
    fresh: Math.abs(nowSeconds - timestamp) <= toleranceSeconds,
    timestamp,
    ageSeconds: nowSeconds - timestamp,
  };
}
