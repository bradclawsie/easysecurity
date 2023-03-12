# easysecurity

Basic security API for Typescript that optimizes for easy use

[![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![ci](https://github.com/bradclawsie/easysecurity/workflows/ci/badge.svg)

## Motivation

I find most security APIs hard to use. What I'm usually looking for is
simple ways to hash values, encrypt/decrypt values, and generate
random strings.

In almost all cases, I want to work with values that
can be printed and stored directly, which for me means using hex
encoding as a serialization format.

This module is not for cryptography experts. This module is not for
people who want to tune parameters. This module is for people for whom
AES-CBC is a "good enough" cipher, for whom v4 UUIDs are a "good
enough" random value, and for whom sha256 is a "good enough" hash.

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

// generate a Crypter using new, random key and IV
// (you can access them via crypter.Key, crypter.IV)
const crypter = Crypter.generate();

// or maybe you already have hex-exported Key and IV that you had stored
const crypter = Crypter.fromHex(hexKey, hexIV);

// or maybe you want to generate new Key and IV
const key = await Key.generate();
const iv = IV.fromString("user@example.com");
const crypter = await new Crypter(key, iv);

// or you want to create Key and IV instances directly from
hex-exports
const key = await Key.fromHex(hexKey);
const iv = IV.fromHex(hexIV);

// and you can make these exports easily:
const hexKey = key.toHex();
const hexIV = iv.toHex();

// to encrypt some clear text:
const clearText = "hello world";
const hexCrypted = await crypter.encryptToHex(clearText);

// ...and get the clear text back
const decrypted = await crypter.decryptFromHex(hexCrypted);

```
