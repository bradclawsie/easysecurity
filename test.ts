import { assertEquals } from "https://deno.land/std@0.179.0/testing/asserts.ts";
import { Crypter, IV, Key, sha256Hex } from "./mod.ts";

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
 *  iv length
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
Deno.test("encrypt", async () => {
  const key = await Key.generate();
  const iv = IV.generate();
  const encrypter = new Crypter(key, iv);
  const clearText = "hello world";
  const hexCrypted = await encrypter.encryptToHex(clearText);
  const decrypted = await encrypter.decryptFromHex(hexCrypted);
  assertEquals(decrypted, clearText, "round trip encrypt decrypt");
});
