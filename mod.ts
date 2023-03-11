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

const AES_CBC = "AES-CBC";

class Key {
  static readonly Params: AesKeyGenParams = { name: AES_CBC, length: 128 };
  static readonly Extractable = true;
  static readonly Usages: KeyUsage[] = ["encrypt", "decrypt"];

  readonly cryptoKey: CryptoKey; // internal representation

  constructor(cryptoKey: CryptoKey) {
    assertEquals(cryptoKey.algorithm, Key.Params, "key algorithm");
    assertEquals(cryptoKey.extractable, Key.Extractable, "key extractable");
    assertEquals(cryptoKey.usages, Key.Usages, "key usages");
    this.cryptoKey = cryptoKey;
  }

  static async create(): Promise<Key> {
    return new Key(
      await crypto.subtle.generateKey(
        Key.Params,
        Key.Extractable,
        Key.Usages,
      ),
    );
  }

  static async fromHex(hexKey: string): Promise<Key> {
    return new Key(
      await crypto.subtle.importKey(
        "raw",
        hexToBytes(hexKey),
        Key.Params,
        Key.Extractable,
        Key.Usages,
      ),
    );
  }

  async toHex(): Promise<string> {
    const keyBytes = new Uint8Array(
      await crypto.subtle.exportKey("raw", this.cryptoKey),
    );
    return bytesToHex(keyBytes);
  }
}

class IV {
  static readonly Length = 16;
  readonly bytes: Uint8Array; // internal representation

  constructor(bytes: Uint8Array) {
    assertEquals(bytes.length, IV.Length, "iv length");
    this.bytes = bytes;
  }

  static fromHex(hexIV: string): IV {
    return new IV(hexToBytes(hexIV));
  }

  toHex(): string {
    return bytesToHex(this.bytes);
  }

  /**
   * @param {string} s - the seed for the IV
   * @returns {Promise<IV>} a 16-byte long Uint8Array suitable as an AEC-CBC IV
   */
  static async fromString(s: string): Promise<IV> {
    assertNotEquals(s.length, 0, "empty iv input");
    return new IV(stringToBytes(await sha256Hex(s)).slice(0, IV.Length));
  }
}

class Encrypter {
  readonly key: Key;
  readonly iv: IV;

  constructor(key: Key, iv: IV) {
    this.key = key;
    this.iv = iv;
  }

  static async fromHex(hexKey: string, hexIV: string): Promise<Encrypter> {
    return new Encrypter(await Key.fromHex(hexKey), IV.fromHex(hexIV));
  }

  async encryptToHex(s: string): Promise<string> {
    return bytesToHex(
      new Uint8Array(
        await crypto.subtle.encrypt(
          { name: AES_CBC, iv: this.iv.bytes },
          this.key.cryptoKey,
          new TextEncoder().encode(s),
        ),
      ),
    );
  }
}

export { Encrypter, IV, Key, randomUUID, sha256Hex };
