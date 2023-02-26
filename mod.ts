import { crypto } from "https://deno.land/std@0.178.0/crypto/crypto.ts";
import { toHashString } from "https://deno.land/std@0.178.0/crypto/to_hash_string.ts";
import { stringToBytes } from "https://deno.land/x/textras@0.1.2/mod.ts";

const sha256Hex = async (s: string): Promise<string> =>
  toHashString(await crypto.subtle.digest("SHA-256", stringToBytes(s)));

export { sha256Hex };
