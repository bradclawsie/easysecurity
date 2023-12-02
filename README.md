# easysecurity

Basic security API for Typescript that optimizes for easy use

[![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![ci](https://github.com/bradclawsie/easysecurity/workflows/ci/badge.svg)

## Important Compatibility Note

The 0.2.0 release breaks compatibility with the previous relesae, 0.1.9. This
was noted in the 0.1.9 README. The changes include:

- Using AES-GCM 256 as the default cipher instead of AES-CBC 128.
- Moving `encryptToHex` and `decryptToHex` to static methods that feature
  per-encrypt IVs automatically generated and prepended to the encrypted
  message.
- Removing the `Crypter` class.

No deprecation notices are included as the change of the cipher implies the need
to regenerate encrypted messages generated with versions prior.

## Motivation

I find most security APIs hard to use. What I'm usually looking for is simple
ways to hash values, encrypt/decrypt values, and generate random strings.

In almost all cases, I want to work with values that can be printed and stored
directly, which for me means using hex encoding as a serialization format.

This module is not for cryptography experts. This module is not for people who
want to tune parameters. This module is for people for whom AES-GCM is a "good
enough" cipher, for whom v4 UUIDs are a "good enough" random value, and for whom
sha256 is a "good enough" hash.

Check out `test.ts` for some good copy-paste code samples.

## Import

```ts
import * as easysecurity from "https://deno.land/x/easysecurity/mod.ts";
```

### Hashing

```ts
sha256Hex(input); // sha256 input and hex-encode
```

### Random Values

```ts
randomUUID(); // re-export crypto.randomUUID();
```

### Encryption/Decryption

```ts
const key = await Key.generate();
const clearText = "hello world";
const hexCryptedWithIV = await encryptToHex(clearText, key);
const decrypted = await decryptFromHex(hexCryptedWithIV, key);
// clearText == decrypted
```
