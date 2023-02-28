import { crypto } from "https://deno.land/std@0.178.0/crypto/crypto.ts";
import { toHashString } from "https://deno.land/std@0.178.0/crypto/to_hash_string.ts";
import { stringToBytes } from "https://deno.land/x/textras@0.1.3/mod.ts";

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
  cryptoKey: CryptoKey;

  constructor(cryptoKey: CryptoKey) {
    this.cryptoKey = cryptoKey;
  }

  static async makeCryptoKey(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: "AES-CBC", length: 128 },
      true,
      ["encrypt", "decrypt"],
    );
  }
}

export { Key, randomUUID, sha256Hex };
