import {
  assert,
  assertEquals,
  assertNotEquals,
} from "https://deno.land/std@0.208.0/assert/mod.ts";
import {
  decryptFromHex,
  encryptToHex,
  isUUID,
  IV,
  Key,
  randomUUID,
  sha256Hex,
} from "./mod.ts";

/**
 * uuid round trip
 */
Deno.test("uuid", () => {
  assert(isUUID(randomUUID()), "uuid round trip");
  assert(!isUUID(randomUUID() + randomUUID()), "not a uuid");
});

/**
 * hex encode to a known value
 */
Deno.test("sha256Hex", async () => {
  const h = await sha256Hex("hello world");
  assertEquals(
    h,
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "sha256hex",
  );
});

/**
 * round trip a key
 */
Deno.test("key", async () => {
  const k0 = await Key.generate();
  // export key to hex
  const h0 = await k0.toHex();
  // import that to a new key
  const k1 = await Key.fromHex(h0);
  // export again
  const h1 = await k1.toHex();
  assertEquals(h0, h1, "key round trip");
});

/**
 *  round trip an IV
 */
Deno.test("iv", async () => {
  const iv = await IV.fromString("hello world");
  assertEquals(iv.bytes.length, IV.Length, "iv length");
  const hexIV = iv.toHex();
  const ivFromHex = IV.fromHex(hexIV);
  assertEquals(ivFromHex.bytes, iv.bytes, "iv round trip");
  assertEquals(ivFromHex.toHex(), hexIV, "hex round trip");
});

/**
 * encrypt/decrypt
 */
Deno.test("encrypt/decrypt", async () => {
  const k = await Key.generate();
  const clearText = "hello world";
  const hexCryptedWithIV = await encryptToHex(clearText, k);
  const decrypted = await decryptFromHex(hexCryptedWithIV, k);
  assertEquals(decrypted, clearText, "round trip encrypt decrypt");
  const hexCryptedWithIV2 = await encryptToHex(clearText, k);
  assertNotEquals(hexCryptedWithIV, hexCryptedWithIV2, "different iv");
  const decrypted2 = await decryptFromHex(hexCryptedWithIV, k);
  assertEquals(decrypted2, clearText, "round trip encrypt decrypt");
});
