import { crypto } from "https://deno.land/std@0.179.0/crypto/crypto.ts";
import { toHashString } from "https://deno.land/std@0.179.0/crypto/to_hash_string.ts";
import {
  assertEquals,
  assertNotEquals,
} from "https://deno.land/std@0.179.0/testing/asserts.ts";
import {
  bytesToHex,
  bytesToString,
  hexToBytes,
  stringToBytes,
} from "https://deno.land/x/textras@0.1.4/mod.ts";

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

/**
 * @class Key provides a simple wrapper for AES CryptoKeys allowing for serialization to hex.
 */
class Key {
  static readonly Params: AesKeyGenParams = { name: AES_CBC, length: 128 };
  static readonly Extractable = true;
  static readonly Usages: KeyUsage[] = ["encrypt", "decrypt"];

  readonly cryptoKey: CryptoKey; // internal representation

  /**
   * @constructor
   * @param {CryptoKey} cryptoKey - caller provided key
   */
  constructor(cryptoKey: CryptoKey) {
    assertEquals(cryptoKey.algorithm, Key.Params, "key algorithm");
    assertEquals(cryptoKey.extractable, Key.Extractable, "key extractable");
    assertEquals(cryptoKey.usages, Key.Usages, "key usages");
    this.cryptoKey = cryptoKey;
  }

  /**
   * construct a new Key based on the exported Key hex representation
   * @param {string} hexKey - previously exported Key hex (from toHex())
   * @returns {Promise<Key>} - a new Key constructed from the hexKey
   */
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

  /**
   * construct a new Key based on a new random seed
   * @returns {Promise<Key>} - a new Key constructed from the random seed
   */
  static async generate(): Promise<Key> {
    return new Key(
      await crypto.subtle.generateKey(
        Key.Params,
        Key.Extractable,
        Key.Usages,
      ),
    );
  }

  /**
   * export the hex serialization of the Key
   * @returns {Promise<string>} - hex serialization of the Key
   */
  async toHex(): Promise<string> {
    const keyBytes = new Uint8Array(
      await crypto.subtle.exportKey("raw", this.cryptoKey),
    );
    return bytesToHex(keyBytes);
  }
}

/**
 * @class IV provides a simple wrapper for AES IVs allowing for serialization to hex.
 */
class IV {
  static readonly Length = 16;
  readonly bytes: Uint8Array; // internal representation

  /**
   * @constructor
   * @param {Uint8Array} bytes - caller provided iv (len 16 Uint8Array)
   */
  constructor(bytes: Uint8Array) {
    assertEquals(bytes.length, IV.Length, "iv length");
    this.bytes = bytes;
  }

  /**
   * construct a new Key based on the exported IV hex representation
   * @param {string} hexIV - previously exported IV hex (from toHex())
   * @returns {Promise<IV>} - a new IV constructed from the hexIV
   */
  static fromHex(hexIV: string): IV {
    return new IV(hexToBytes(hexIV));
  }

  /**
   * construct a new IV using a provided string as the seed
   * @param {string} s - the seed for the IV
   * @returns {Promise<IV>} a 16-byte long Uint8Array suitable as an AEC-CBC IV
   */
  static async fromString(s: string): Promise<IV> {
    assertNotEquals(s.length, 0, "empty iv input");
    return new IV(stringToBytes(await sha256Hex(s)).slice(0, IV.Length));
  }

  /**
   * construct a new IV based on a new random seed
   * @returns {Promise<IV>} - a new IV constructed from the random seed
   */
  static generate(): IV {
    return new IV(crypto.getRandomValues(new Uint8Array(IV.Length)));
  }

  /**
   * export the hex serialization of the IV
   * @returns {Promise<string>} - hex serialization of the IV
   */
  toHex(): string {
    return bytesToHex(this.bytes);
  }
}

/**
 * @class Crypter provides a simple wrapper for encrypting to and decrypting from hex-encoded values
 */
class Crypter {
  readonly key: Key;
  readonly iv: IV;

  /**
   * @constructor
   * @param {Key} key - the encryption Key
   * @param {IV} iv - the encryption IV
   */
  constructor(key: Key, iv: IV) {
    this.key = key;
    this.iv = iv;
  }

  /**
   * construct a new Crypter using a hex-encoded Key and IV
   * @param {string} hexKey - the hex-encoded encryption Key (from Key.toHex())
   * @param {string} hexIV - the hex-encoded encryption IV (from IV.toHex())
   * @returns {Promise<Crypter>} - a new Crypter constructed from hexKey and hexIV
   */
  static async fromHex(hexKey: string, hexIV: string): Promise<Crypter> {
    return new Crypter(await Key.fromHex(hexKey), IV.fromHex(hexIV));
  }

  /**
   * construct a new Crypter using newly generated Key and IV
   * @returns {Promise<Crypter>} - a new Crypter constructed with generated Key and IV
   */
  static async generate(): Promise<Crypter> {
    return new Crypter(await Key.generate(), IV.generate());
  }

  /**
   * decrypt a hex-encoded encryption output and return the original clear text
   * @param {string} hexEncrypted - the output of a previous call to encryptToHex
   * @returns {Promise<string>} - the decrypted clear text
   */
  async decryptFromHex(hexEncrypted: string): Promise<string> {
    return bytesToString(
      new Uint8Array(
        await crypto.subtle.decrypt(
          { name: AES_CBC, iv: this.iv.bytes },
          this.key.cryptoKey,
          hexToBytes(hexEncrypted),
        ),
      ),
    );
  }

  /**
   * encrypt a clear text and hex-encode the resulting encrypted value
   * @param {string} clearText - the string to encrypt
   * @returns {Promise<string>} - the decrypted clear text
   */
  async encryptToHex(clearText: string): Promise<string> {
    return bytesToHex(
      new Uint8Array(
        await crypto.subtle.encrypt(
          { name: AES_CBC, iv: this.iv.bytes },
          this.key.cryptoKey,
          stringToBytes(clearText),
        ),
      ),
    );
  }
}

export { Crypter, IV, Key, randomUUID, sha256Hex };
