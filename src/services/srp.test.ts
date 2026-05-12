import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  computeVerifier,
  computeX,
  G,
  generateServerKeypair,
  K,
  modPow,
  N,
  N_BYTE_LENGTH,
  padHex,
  padHexBytes,
  srpPoolName,
  verifyClaimSignature,
} from "./srp";

const HKDF_INFO = Buffer.from("Caldera Derived Key", "utf-8");

/**
 * Reference client-side SRP signature computation, matching exactly what
 * amazon-cognito-identity-js does when responding to a PASSWORD_VERIFIER
 * challenge. The server-side `verifyClaimSignature` must agree on every byte.
 */
function clientSign(args: {
  poolName: string;
  username: string;
  password: string;
  salt: Buffer;
  srpA: bigint;
  srpB: bigint;
  smallA: bigint;
  secretBlock: Buffer;
  timestamp: string;
}): { claimSignatureBase64: string } {
  const {
    poolName,
    username,
    password,
    salt,
    srpA,
    srpB,
    smallA,
    secretBlock,
    timestamp,
  } = args;

  const u = BigInt(
    `0x${createHash("sha256")
      .update(Buffer.concat([padHexBytes(srpA), padHexBytes(srpB)]))
      .digest("hex")}`,
  );

  const x = computeX(poolName, username, password, salt);

  // S = (B - k * g^x)^(a + u*x) mod N
  // Compute (B - k * g^x) mod N first, taking care that the subtraction may
  // dip negative before reducing.
  const kgx = (K * modPow(G, x, N)) % N;
  let base = (srpB - kgx) % N;
  if (base < 0n) base += N;
  const S = modPow(base, smallA + u * x, N);

  const kAuth = Buffer.from(
    hkdfSync("sha256", padHexBytes(S), padHexBytes(u), HKDF_INFO, 16),
  );

  const sig = createHmac("sha256", kAuth)
    .update(Buffer.from(poolName, "utf-8"))
    .update(Buffer.from(username, "utf-8"))
    .update(secretBlock)
    .update(Buffer.from(timestamp, "utf-8"))
    .digest();

  return { claimSignatureBase64: sig.toString("base64") };
}

describe("srp", () => {
  describe("constants", () => {
    it("N is the 3072-bit Cognito prime", () => {
      expect(N.toString(16).length).toBe(N_BYTE_LENGTH * 2);
      // N starts with FFFF... and ends with ...FFFFFFFFFFFFFFFF
      const hex = N.toString(16).toUpperCase();
      expect(hex.startsWith("FFFFFFFFFFFFFFFF")).toBe(true);
      expect(hex.endsWith("FFFFFFFFFFFFFFFF")).toBe(true);
    });

    it("g is 2", () => {
      expect(G).toBe(2n);
    });

    it("k = H(PAD(N) || PAD(g)) is non-zero and bounded by N", () => {
      expect(K > 0n).toBe(true);
      expect(K < N).toBe(true);
    });
  });

  describe("padHex", () => {
    it("pads odd-length hex to even", () => {
      expect(padHex(0x2n)).toBe("02");
      expect(padHex(0xabcn)).toBe("0abc");
    });

    it("prepends 00 when the high nibble has the high bit set", () => {
      // 0xFF would otherwise be misread as signed -1.
      expect(padHex(0xffn)).toBe("00ff");
      expect(padHex(0x80n)).toBe("0080");
    });

    it("leaves an even-length, high-bit-clear value alone", () => {
      expect(padHex(0x1234n)).toBe("1234");
    });
  });

  describe("modPow", () => {
    it("matches BigInt ** for small inputs", () => {
      expect(modPow(3n, 5n, 1000n)).toBe(243n);
      expect(modPow(10n, 0n, 7n)).toBe(1n);
    });

    it("handles modulus 1", () => {
      expect(modPow(5n, 100n, 1n)).toBe(0n);
    });

    it("returns the verifier within [0, N)", () => {
      const v = computeVerifier(123n);
      expect(v >= 0n).toBe(true);
      expect(v < N).toBe(true);
    });
  });

  describe("srpPoolName", () => {
    it("returns the slice after the underscore", () => {
      expect(srpPoolName("us-east-1_AbCd123")).toBe("AbCd123");
    });

    it("returns the full id when there's no underscore", () => {
      expect(srpPoolName("noregion")).toBe("noregion");
    });
  });

  describe("verifyClaimSignature", () => {
    const poolName = "AbCd123";
    const username = "11111111-2222-3333-4444-555555555555";
    const password = "correct horse battery staple";
    const timestamp = "Tue May 12 08:34:30 UTC 2026";

    const runRoundTrip = (clientPassword: string) => {
      // Server side: derive salt + verifier from the *stored* password and
      // produce (b, B).
      const salt = randomBytes(16);
      const x = computeX(poolName, username, password, salt);
      const v = computeVerifier(x);
      const { b, B } = generateServerKeypair(v);
      const secretBlock = randomBytes(64);

      // Client side: choose a private key a, derive A = g^a mod N, and sign
      // using whatever password it thinks it has.
      const smallA = BigInt(`0x${randomBytes(32).toString("hex")}`) % N;
      const A = modPow(G, smallA, N);

      const { claimSignatureBase64 } = clientSign({
        poolName,
        username,
        password: clientPassword,
        salt,
        srpA: A,
        srpB: B,
        smallA,
        secretBlock,
        timestamp,
      });

      return verifyClaimSignature({
        poolName,
        username,
        password,
        salt,
        A,
        B,
        b,
        secretBlock,
        timestamp,
        claimSignatureBase64,
        claimSecretBlockBase64: secretBlock.toString("base64"),
      });
    };

    it("accepts the correct password", () => {
      expect(runRoundTrip(password)).toBe(true);
    });

    it("rejects a wrong password", () => {
      expect(runRoundTrip("totally wrong")).toBe(false);
    });

    it("rejects a tampered secret block echo", () => {
      const salt = randomBytes(16);
      const x = computeX(poolName, username, password, salt);
      const v = computeVerifier(x);
      const { b, B } = generateServerKeypair(v);
      const secretBlock = randomBytes(64);
      const smallA = BigInt(`0x${randomBytes(32).toString("hex")}`) % N;
      const A = modPow(G, smallA, N);

      const { claimSignatureBase64 } = clientSign({
        poolName,
        username,
        password,
        salt,
        srpA: A,
        srpB: B,
        smallA,
        secretBlock,
        timestamp,
      });

      // Client echoes back a *different* secret block.
      const tamperedEcho = randomBytes(64).toString("base64");
      expect(
        verifyClaimSignature({
          poolName,
          username,
          password,
          salt,
          A,
          B,
          b,
          secretBlock,
          timestamp,
          claimSignatureBase64,
          claimSecretBlockBase64: tamperedEcho,
        }),
      ).toBe(false);
    });

    it("rejects A === 0 mod N", () => {
      const salt = randomBytes(16);
      const x = computeX(poolName, username, password, salt);
      const v = computeVerifier(x);
      const { b, B } = generateServerKeypair(v);
      const secretBlock = randomBytes(64);

      expect(
        verifyClaimSignature({
          poolName,
          username,
          password,
          salt,
          A: 0n,
          B,
          b,
          secretBlock,
          timestamp,
          claimSignatureBase64: Buffer.alloc(32).toString("base64"),
          claimSecretBlockBase64: secretBlock.toString("base64"),
        }),
      ).toBe(false);
    });
  });
});
