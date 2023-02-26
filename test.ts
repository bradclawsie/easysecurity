import { assertEquals } from "https://deno.land/std@0.178.0/testing/asserts.ts";
import { sha256Hex } from "./mod.ts";

Deno.test("sha256Hex", async () => {
  const h = await sha256Hex("hello world");
  assertEquals(
    h,
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "sha256hex",
  );
});
