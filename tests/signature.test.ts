import { expect, it } from "vitest";
import { hmacSha256, timestampAge, verifyStripe } from "../src/signature";
it("matches RFC 4231 HMAC-SHA-256 test case 1", async () => {
  expect(await hmacSha256(new Uint8Array(20).fill(0x0b), "Hi There")).toBe(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  );
});
it("keeps raw-body signature and freshness independent", async () => {
  const raw = '{ "id": "synthetic-47" }';
  const secret = "synthetic-session-key";
  const digest = await hmacSha256(
    new TextEncoder().encode(secret),
    `1000.${raw}`,
  );
  const header = `t=1000,v1=${digest}`;
  expect(await verifyStripe(raw, header, secret, 1050)).toMatchObject({
    matches: true,
    fresh: true,
  });
  expect(
    await verifyStripe(JSON.stringify(JSON.parse(raw)), header, secret, 1050),
  ).toMatchObject({ matches: false, fresh: true });
  expect(await verifyStripe(raw, header, secret, 1600)).toMatchObject({
    matches: true,
    fresh: false,
  });
});
it("rejects ambiguous timestamps and missing signatures", async () => {
  await expect(verifyStripe("{}", "t=1,t=2,v1=x", "key", 1)).rejects.toThrow(
    "exactly one",
  );
  await expect(verifyStripe("{}", "t=1", "key", 1)).rejects.toThrow("v1");
});

it("describes past and future signature timestamps accurately", () => {
  expect(timestampAge(902)).toBe("902 seconds ago");
  expect(timestampAge(-902)).toBe("902 seconds ahead of the current time");
  expect(timestampAge(0)).toBe("at the current time");
});

it("rejects malformed signature bytes with an otherwise valid timestamp", async () => {
  await expect(
    verifyStripe("{}", "t=1000,v1=not-a-digest", "synthetic-key-123", 1000),
  ).rejects.toThrow("64 hexadecimal");
});
