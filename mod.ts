import { crypto } from "https://deno.land/std@0.178.0/crypto/crypto.ts";
import { toHashString } from "https://deno.land/std@0.178.0/crypto/to_hash_string.ts";
import {
  assertEquals,
  assertNotEquals,
} from "https://deno.land/std@0.178.0/testing/asserts.ts";
import {
  bytesToHex,
  hexToBytes,
  stringToBytes,
} from "https://deno.land/x/textras@0.1.3/mod.ts";

/**
 * produce the hex-encoded string of the sha256 hash of string s
 * @param {string} s - the string to hash
 * @returns {Promise<string>} the hex-encoded sha256 of s
 */
const sha256Hex = async (s: string): Promise<string> =>
  toHashString(await crypto.subtle.digest("SHA-256", stringToBytes(s)));

/**
 * re-export crypto.randomUUID in this namespace
 * @returns {string} a random v4 uuid
 */
const randomUUID = (): string => crypto.randomUUID();

class Key {
  static readonly Params: AesKeyGenParams = { name: "AES-CBC", length: 128 };
  static readonly Extractable = true;
  static readonly Usages: KeyUsage[] = ["encrypt", "decrypt"];

  readonly cryptoKey: CryptoKey;

  constructor(cryptoKey: CryptoKey) {
    assertEquals(cryptoKey.algorithm, Key.Params, "key algorithm");
    assertEquals(cryptoKey.extractable, Key.Extractable, "key extractable");
    assertEquals(cryptoKey.usages, Key.Usages, "key usages");
    this.cryptoKey = cryptoKey;
  }

  async toHex(): Promise<string> {
    const keyBytes = new Uint8Array(
      await crypto.subtle.exportKey("raw", this.cryptoKey),
    );
    return bytesToHex(keyBytes);
  }

  static async fromHex(hexKey: string): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      "raw",
      hexToBytes(hexKey),
      Key.Params,
      Key.Extractable,
      Key.Usages,
    );
  }

  static async create(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      Key.Params,
      Key.Extractable,
      Key.Usages,
    );
  }
}

/**
 * @param {string} s - the seed for the IV
 * @returns {Promise<Uint8Array>} a 16-byte long Uint8Array suitable as an AEC-CBC IV
 */
const stringToIV = async (s: string): Promise<Uint8Array> => {
  assertNotEquals(s.length, 0, "empty iv input");
  return stringToBytes(await sha256Hex(s)).slice(0, 16);
};

export { Key, randomUUID, sha256Hex, stringToIV };
