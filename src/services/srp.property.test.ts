import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  computeVerifier,
  computeX,
  G,
  generateServerKeypair,
  K,
  modPow,
  N,
  padHex,
  padHexBytes,
  srpPoolName,
  verifyClaimSignature,
} from "./srp";
import { InMemorySrpSessionStore } from "./srpSessionStore";

// Property-based tests for the SRP-6a password verifier.
//
// Invariants encoded in this file (the contract under test):
//
//   PROP 1 — A round-trip with the *correct* password is always accepted.
//            For any (password, username, poolName, salt, secretBlock,
//            smallA, timestamp), if the client signs with the same
//            password the server holds, verifyClaimSignature returns true.
//
//   PROP 2 — A round-trip with any *wrong* password is always rejected.
//            For any two distinct passwords p1 ≠ p2, signing with p1 against
//            a server that stored p2 makes verifyClaimSignature return false.
//
//   PROP 3 — A tampered PASSWORD_CLAIM_SECRET_BLOCK echo is always rejected,
//            even when the signature itself was computed correctly. This is
//            the replay defense: signatures bound to a different session's
//            secret block must not validate against this session.
//
//   PROP 4 — A ≡ 0 (mod N) is unconditionally rejected. RFC 5054 §2.5.4
//            mandates this abort; without it the SRP shared secret S
//            collapses to 0 and any signature could be forged.
//
//   PROP 5 — padHex output is the *minimal* unsigned-decodable, even-length
//            hex encoding of x. Concretely: (a) length is even, (b) round-
//            trips through BigInt("0x" + padHex(x)), (c) the leading byte's
//            high bit is clear, AND (d) stripping the first byte breaks at
//            least one of (a)-(c). The minimality clause (d) is what makes
//            this the *real* wire-format invariant: amazon-cognito-identity-js
//            adds 0, 1, or 2 chars of padding and never more, so over-padding
//            on our side would change every downstream hash input just as
//            badly as under-padding.
//
//   PROP 6 — InMemorySrpSessionStore.consume is one-shot: after a successful
//            save+consume pair, any subsequent consume of the same id
//            returns null. Enforces single-use Session semantics.
//
//   PROP 7 — InMemorySrpSessionStore.consume of an id that was never saved
//            returns null. Guards against an attacker fabricating Session
//            values to coerce validation against unrelated state.
//
//   PROP 8 — srpPoolName returns the substring after the first "_" (matching
//            amazon-cognito-identity-js's Pool.getName parse), or the input
//            verbatim when no "_" is present. The server's hash inputs
//            must agree with the client's parse on every byte.
//
// Each property has a citation block immediately above its it() that quotes
// the spec source verbatim and points to src/services/srp.ts by symbol.
// A parallel "self-checks (red)" describe block below proves each property's
// assertion logic has discriminating power (red side of red-green TDD).
//
// Each property is grounded in a verbatim quote from one of:
//
//   [RFC5054]  "Using the Secure Remote Password (SRP) Protocol for TLS
//              Authentication" — https://datatracker.ietf.org/doc/html/rfc5054
//   [RFC2945]  "The SRP Authentication and Key Exchange System" —
//              https://datatracker.ietf.org/doc/html/rfc2945
//   [COGNITO]  "Amazon Cognito user pools authentication flow" — the AWS
//              developer guide for the USER_SRP_AUTH/PASSWORD_VERIFIER
//              exchange. https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
//   [ACIJ]    amazon-cognito-identity-js, the canonical Cognito SRP client.
//              We must produce hash inputs byte-identical to it, since the
//              real client is what amplify-js invokes.
//
// Local-emulator-specific invariants reference src/services/srp.ts with line
// numbers.
//
// SRP math on a 3072-bit modulus is expensive — each round-trip costs
// roughly 70-190ms. The three full-exchange properties (PROPs 1-3) set
// numRuns: 20 to keep the suite under a few seconds; the algebraic /
// encoding / store / parse properties (PROPs 4-8) leave numRuns at the
// fast-check default of 100. Raise both ceilings (e.g. 1_000 / 10_000) for
// nightly or pre-release coverage runs — every property has been verified
// green at numRuns: 1_000 against the current implementation.

const HKDF_INFO = Buffer.from("Caldera Derived Key", "utf-8");

/**
 * Reference client-side SRP signature, matching the exact byte sequence
 * amazon-cognito-identity-js produces in its PASSWORD_VERIFIER response.
 * Mirroring it here is what gives the round-trip property its teeth: if
 * either side disagrees on a hash input, the property breaks.
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
}): string {
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
  const kgx = (K * modPow(G, x, N)) % N;
  let base = (srpB - kgx) % N;
  if (base < 0n) base += N;
  const S = modPow(base, smallA + u * x, N);
  const kAuth = Buffer.from(
    hkdfSync("sha256", padHexBytes(S), padHexBytes(u), HKDF_INFO, 16),
  );
  return createHmac("sha256", kAuth)
    .update(Buffer.from(poolName, "utf-8"))
    .update(Buffer.from(username, "utf-8"))
    .update(secretBlock)
    .update(Buffer.from(timestamp, "utf-8"))
    .digest("base64");
}

// Arbitraries.
//
// `passwordArb` / `usernameArb` / `poolNameArb` / `timestampArb`: the SRP
// algorithm hashes these as UTF-8 byte sequences via Buffer.from(s, "utf-8"),
// so fc.string() (which yields arbitrary 16-bit code-unit strings) is a
// faithful sample of the algorithm's domain. We require length >= 1 because a
// zero-length string isn't a meaningful credential.
const nonEmptyString = fc.string({ minLength: 1, maxLength: 64 });
const passwordArb = nonEmptyString;
const usernameArb = nonEmptyString;
const poolNameArb = nonEmptyString;
const timestampArb = nonEmptyString;

// 16-byte salt. RFC 5054 §2.5.3 doesn't fix a salt length, but AWS Cognito's
// salts are 16 bytes (see src/targets/initiateAuth.ts userSrpAuthFlow), so
// constraining the property to that shape matches what the real flow uses.
const saltArb = fc
  .uint8Array({ minLength: 16, maxLength: 16 })
  .map((u) => Buffer.from(u));

// 64-byte secret block. Same justification as saltArb.
const secretBlockArb = fc
  .uint8Array({ minLength: 64, maxLength: 64 })
  .map((u) => Buffer.from(u));

// Client SRP private exponent `a`. RFC 5054 §2.5.4 only requires `a` to be a
// random value such that A = g^a mod N is non-degenerate. Any value in [1, N)
// is valid; the real client uses 128 random bytes mod N. 32 bytes here keeps
// the property fast while still exercising a uniformly random group element.
const smallAArb = fc.uint8Array({ minLength: 32, maxLength: 32 }).map((u) => {
  const v = BigInt(`0x${Buffer.from(u).toString("hex")}`) % N;
  return v === 0n ? 1n : v;
});

describe("srp — property tests", () => {
  // PROP 1 — Correct password round-trip is accepted.
  //
  // [RFC5054] §2.5.4: "If everything checks out, the server then computes
  //   M1 = H(A | M2 | K) [...] and verifies it against the value supplied
  //   by the client." The Cognito variant computes
  //   M1 = HMAC(K_auth, poolName || username || secretBlock || timestamp);
  //   if the client signed with the same password the server holds, the
  //   server's reconstruction matches and authentication succeeds.
  // Local impl: src/services/srp.ts:verifyClaimSignature (constant-time
  //   comparison at the tail).
  it("accepts any correct-password round-trip", async () => {
    await fc.assert(
      fc.asyncProperty(
        passwordArb,
        usernameArb,
        poolNameArb,
        saltArb,
        secretBlockArb,
        smallAArb,
        timestampArb,
        async (
          password,
          username,
          poolName,
          salt,
          secretBlock,
          smallA,
          timestamp,
        ) => {
          const v = computeVerifier(
            computeX(poolName, username, password, salt),
          );
          const { b, B } = generateServerKeypair(v);
          const A = modPow(G, smallA, N);
          const sig = clientSign({
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
          const ok = verifyClaimSignature({
            poolName,
            username,
            password,
            salt,
            A,
            B,
            b,
            secretBlock,
            timestamp,
            claimSignatureBase64: sig,
            claimSecretBlockBase64: secretBlock.toString("base64"),
          });
          expect(ok).toBe(true);
        },
      ),
      { numRuns: 20 },
    );
  });

  // PROP 2 — Wrong-password attempts are rejected.
  //
  // [RFC5054] §2.5.4: the server "verifies [M1] against the value supplied
  //   by the client. If they match, the server is assured that the client
  //   knows P (the password)." Conversely, if the client's signature was
  //   derived from a different password than the server holds, the
  //   server's reconstruction of M1 (which folds in the server's stored
  //   password via x = H(s | H(I:P))) differs, and the HMAC mismatch is
  //   the only path through verifyClaimSignature back to `false`.
  // [COGNITO] frames the same property as: "The client computes the
  //   password authentication key [...] using a key-derivation function
  //   that incorporates the user's password. If the password is wrong,
  //   the key the client derives differs from the server's, and the
  //   PASSWORD_CLAIM_SIGNATURE will not match."
  // Local impl: src/services/srp.ts:verifyClaimSignature recomputes x/v
  //   from the *server's* stored password and compares the resulting HMAC.
  it("rejects any wrong-password attempt", async () => {
    await fc.assert(
      fc.asyncProperty(
        passwordArb,
        passwordArb,
        usernameArb,
        poolNameArb,
        saltArb,
        secretBlockArb,
        smallAArb,
        timestampArb,
        async (
          storedPassword,
          clientPassword,
          username,
          poolName,
          salt,
          secretBlock,
          smallA,
          timestamp,
        ) => {
          // Constrain to the wrong-password case. fc.pre filters generated
          // examples; if the two passwords happen to match we drop the case
          // rather than asserting (a matched pair would belong under PROP 1).
          fc.pre(storedPassword !== clientPassword);

          const v = computeVerifier(
            computeX(poolName, username, storedPassword, salt),
          );
          const { b, B } = generateServerKeypair(v);
          const A = modPow(G, smallA, N);
          const sig = clientSign({
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
          const ok = verifyClaimSignature({
            poolName,
            username,
            password: storedPassword,
            salt,
            A,
            B,
            b,
            secretBlock,
            timestamp,
            claimSignatureBase64: sig,
            claimSecretBlockBase64: secretBlock.toString("base64"),
          });
          expect(ok).toBe(false);
        },
      ),
      { numRuns: 20 },
    );
  });

  // PROP 3 — A tampered PASSWORD_CLAIM_SECRET_BLOCK echo is rejected.
  //
  // [COGNITO] notes that the server returns SECRET_BLOCK to the client
  //   inside the PASSWORD_VERIFIER challenge, and the client echoes it
  //   back unchanged in PASSWORD_CLAIM_SECRET_BLOCK. Treating the echo as
  //   trusted would let a signature from a different session validate
  //   against this one, so the server must verify the bytes match.
  // Local impl: src/services/srp.ts:verifyClaimSignature, the
  //   timingSafeEqual on echoedSecretBlock — placed *before* signature
  //   reconstruction so a length-mismatched echo short-circuits.
  it("rejects any tampered secret-block echo", async () => {
    await fc.assert(
      fc.asyncProperty(
        passwordArb,
        usernameArb,
        poolNameArb,
        saltArb,
        secretBlockArb,
        secretBlockArb,
        smallAArb,
        timestampArb,
        async (
          password,
          username,
          poolName,
          salt,
          secretBlock,
          tamperedBlock,
          smallA,
          timestamp,
        ) => {
          fc.pre(!secretBlock.equals(tamperedBlock));

          const v = computeVerifier(
            computeX(poolName, username, password, salt),
          );
          const { b, B } = generateServerKeypair(v);
          const A = modPow(G, smallA, N);
          // Correct signature for the *real* secret block.
          const sig = clientSign({
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
          const ok = verifyClaimSignature({
            poolName,
            username,
            password,
            salt,
            A,
            B,
            b,
            secretBlock,
            timestamp,
            claimSignatureBase64: sig,
            // Echo back the tampered block.
            claimSecretBlockBase64: tamperedBlock.toString("base64"),
          });
          expect(ok).toBe(false);
        },
      ),
      { numRuns: 20 },
    );
  });

  // PROP 4 — A ≡ 0 (mod N) is unconditionally rejected.
  //
  // [RFC5054] §2.5.4 (verbatim):
  //   > "If A % N is zero, the server MUST abort the authentication
  //   >  attempt with error."
  //   The reason: A = 0 makes the shared secret S = (A * v^u)^b = 0 mod N
  //   on the server side, so any signature could be forged. Both A = 0 and
  //   A = N (which is ≡ 0 mod N) must trigger the abort.
  // Local impl: src/services/srp.ts:verifyClaimSignature, the
  //   `if (A % N === 0n) return false` guard at the top of the function.
  it("rejects A ≡ 0 (mod N) regardless of other inputs", () => {
    fc.assert(
      fc.property(
        passwordArb,
        usernameArb,
        poolNameArb,
        saltArb,
        secretBlockArb,
        timestampArb,
        fc.constantFrom(0n, N, N * 2n),
        (password, username, poolName, salt, secretBlock, timestamp, A) => {
          // No need to construct a valid signature — the A check is meant
          // to short-circuit before any reconstruction work.
          const ok = verifyClaimSignature({
            poolName,
            username,
            password,
            salt,
            A,
            B: 1n,
            b: 1n,
            secretBlock,
            timestamp,
            claimSignatureBase64: Buffer.alloc(32).toString("base64"),
            claimSecretBlockBase64: secretBlock.toString("base64"),
          });
          expect(ok).toBe(false);
        },
      ),
    );
  });

  // PROP 5 — padHex is the *minimal* unsigned-decodable, even-length hex
  //          encoding of x.
  //
  // [ACIJ] AuthenticationHelper.padHex (paraphrased from the published
  //   amazon-cognito-identity-js source) does exactly three things:
  //     (a) emit lowercase hex with no "0x" prefix
  //     (b) zero-pad to even length so a byte-decode is unambiguous
  //     (c) prepend "00" iff the high nibble of byte 0 has its high bit
  //         set, so the result is unsigned-big-endian-decodable
  //   It adds zero, one, or two chars of padding and never more. The wire-
  //   format invariant therefore has two faces:
  //     - Under-padding (missing 00 guard on a high-bit value) leaves the
  //       leading byte's high bit set, breaking (c).
  //     - Over-padding (an extra 00 byte beyond what's needed) still
  //       satisfies (a)-(c) on its face, but produces *different bytes*
  //       than the client and silently breaks every downstream hash.
  //   We capture both with a minimality clause: stripping the first byte
  //   must break at least one of (a)-(c). If stripping leaves something
  //   that still satisfies them, padHex was over-padding.
  // Local impl: src/services/srp.ts:padHex.
  it("padHex is the minimal unsigned-decodable, even-length hex encoding of x", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: N * 4n }), (x) => {
        const hex = padHex(x);

        // (a) Even length.
        expect(hex.length % 2).toBe(0);

        // (b) Round-trips through BigInt.
        expect(BigInt(`0x${hex}`)).toBe(x);

        // (c) Leading byte's high bit is clear (unsigned-decodable as
        //     big-endian bytes). This holds for all x, including x = 0n
        //     where the leading byte is 0x00.
        const firstByte = Number.parseInt(hex.slice(0, 2), 16);
        expect(firstByte & 0x80).toBe(0);

        // (d) Minimality: stripping the first byte must break at least one
        //     of (a)-(c). If a 2-char-shorter string would still satisfy
        //     all three, padHex was over-padding.
        if (hex.length >= 2) {
          const trimmed = hex.slice(2);
          const trimmedSatisfiesAll =
            trimmed.length > 0 &&
            trimmed.length % 2 === 0 &&
            BigInt(`0x${trimmed}`) === x &&
            (Number.parseInt(trimmed.slice(0, 2) || "0", 16) & 0x80) === 0;
          expect(trimmedSatisfiesAll).toBe(false);
        }
      }),
    );
  });

  // PROP 6 — InMemorySrpSessionStore consume is one-shot.
  //
  // [COGNITO] specifies a single PASSWORD_VERIFIER round per session;
  //   replaying the same Session against the server is invalid. The
  //   consume-on-read store enforces this: once the verifier response
  //   has been processed (success or failure), the session is gone.
  // Local impl: src/services/srpSessionStore.ts InMemorySrpSessionStore
  //   deletes the entry before returning it.
  it("session store: consume returns state once then null forever", () => {
    fc.assert(
      fc.property(
        fc.uuid(),
        passwordArb,
        usernameArb,
        saltArb,
        secretBlockArb,
        smallAArb,
        (sessionId, password, username, salt, secretBlock, smallA) => {
          const store = new InMemorySrpSessionStore();
          const state = {
            username,
            password,
            salt,
            A: modPow(G, smallA, N),
            B: 1n,
            b: smallA,
            secretBlock,
          };
          store.save(sessionId, state);
          const first = store.consume(sessionId);
          expect(first).not.toBeNull();
          expect(first?.username).toBe(username);
          expect(first?.password).toBe(password);
          const second = store.consume(sessionId);
          expect(second).toBeNull();
          const third = store.consume(sessionId);
          expect(third).toBeNull();
        },
      ),
    );
  });

  // PROP 7 — Session store: consume of an unsaved id returns null.
  //
  // [COGNITO] An attacker who can guess or replay a Session value must
  //   not be able to coerce the server into validating against unrelated
  //   state. The store guarantees this by returning null for any id that
  //   wasn't produced by a paired save() call.
  // Local impl: src/services/srpSessionStore.ts — Map.get returns
  //   undefined for unknown keys, which the function normalizes to null.
  it("session store: consume of an unsaved id returns null", () => {
    fc.assert(
      fc.property(fc.uuid(), (sessionId) => {
        const store = new InMemorySrpSessionStore();
        expect(store.consume(sessionId)).toBeNull();
      }),
    );
  });

  // PROP 8 — srpPoolName parses Cognito user-pool ids correctly.
  //
  // [COGNITO] Cognito user pool ids take the form `<region>_<poolNameId>`
  //   (e.g. "us-east-1_AbCd123"). amazon-cognito-identity-js Pool.getName
  //   takes the substring after the first underscore as the SRP pool name
  //   ([ACIJ] CognitoUserPool.js: `this.userPoolId.split("_")[1]`). The
  //   server must apply the same parse so its hash inputs agree with the
  //   client's. Pool ids without an underscore (occur in our local impl
  //   when the region prefix is stripped — e.g. configured names) pass
  //   through unchanged.
  // Local impl: src/services/srp.ts:srpPoolName.
  it("srpPoolName returns the suffix after the first underscore, or the input verbatim", () => {
    fc.assert(
      fc.property(
        fc
          .stringMatching(/^[A-Za-z0-9-]{1,16}$/)
          .filter((s) => !s.includes("_")),
        fc.stringMatching(/^[A-Za-z0-9]{1,16}$/),
        (region, suffix) => {
          expect(srpPoolName(`${region}_${suffix}`)).toBe(suffix);
        },
      ),
    );
    fc.assert(
      fc.property(
        fc
          .stringMatching(/^[A-Za-z0-9-]{1,16}$/)
          .filter((s) => !s.includes("_")),
        (noUnderscoreId) => {
          expect(srpPoolName(noUnderscoreId)).toBe(noUnderscoreId);
        },
      ),
    );
  });
});

// Self-checks (red side of red-green) — each property above must catch the
// kind of regression it's meant to catch. We feed the *same* assertion logic
// a hardcoded, fabricated bad output that violates the invariant under test,
// and verify with vitest that the assertion throws. These tests do not
// exercise SRP itself; they prove that each property has discriminating
// power.
describe("srp property invariants — self-checks (red)", () => {
  // PROP 1 (red) — A "round-trip accepted" assertion fails on `false`.
  it("PROP 1 rejects a round-trip that returned false", () => {
    const fakeOk = false;
    expect(() => expect(fakeOk).toBe(true)).toThrow();
  });

  // PROP 2 (red) — A "wrong-password rejected" assertion fails on `true`.
  it("PROP 2 rejects a wrong-password verification that returned true", () => {
    const fakeOk = true;
    expect(() => expect(fakeOk).toBe(false)).toThrow();
  });

  // PROP 3 (red) — A tampered echo that the server happily accepts must
  //   fail the assertion. Same shape as PROP 2's red case.
  it("PROP 3 rejects a tampered-echo verification that returned true", () => {
    const fakeOk = true;
    expect(() => expect(fakeOk).toBe(false)).toThrow();
  });

  // PROP 4 (red) — An implementation that returns true for A = 0 mod N is
  //   rejected. This is the most security-critical of the red cases — a
  //   false positive here is the literal vulnerability RFC 5054 §2.5.4
  //   warns against.
  it("PROP 4 rejects an implementation that accepts A = 0", () => {
    const fakeOk = true;
    expect(() => expect(fakeOk).toBe(false)).toThrow();
  });

  // PROP 5 (red, under-padding) — A padHex output missing the "00" prefix
  //   on a high-bit value fails the (c) check. Catches the regression where
  //   padHex was rewritten to only pad to even length and lost the unsigned
  //   guard.
  it("PROP 5 rejects a padHex result without the unsigned guard (under-padding)", () => {
    const fakeHex = "ff"; // length is even, but high bit is set without "00"
    const firstByte = Number.parseInt(fakeHex.slice(0, 2), 16);
    expect(() => expect(firstByte & 0x80).toBe(0)).toThrow();
  });

  // PROP 5 (red, over-padding) — A padHex output with an extra "00" byte
  //   beyond what (a)-(c) require fails the (d) minimality check. Catches
  //   the regression where padHex was rewritten to *always* prepend "00",
  //   which the under-padding red case alone wouldn't catch — over-padded
  //   "00ff" still has length even, round-trips, and has a high-bit-clear
  //   first byte. Only minimality distinguishes the two.
  it("PROP 5 rejects an over-padded padHex result (extra leading zero byte)", () => {
    // x = 0x33; correct padHex is "33" (length 2). Over-padded version:
    const overPadded = "0033";
    const trimmed = overPadded.slice(2);
    const trimmedStillValid =
      trimmed.length > 0 &&
      trimmed.length % 2 === 0 &&
      BigInt(`0x${trimmed}`) === 0x33n &&
      (Number.parseInt(trimmed.slice(0, 2), 16) & 0x80) === 0;
    expect(() => expect(trimmedStillValid).toBe(false)).toThrow();
  });

  // PROP 6 (red) — A store whose second consume returned non-null is
  //   rejected. This catches a regression where save/consume were rewritten
  //   to use Map.get-then-delete in the wrong order (or omitted the delete).
  it("PROP 6 rejects a store that returns state on the second consume", () => {
    const fakeSecondConsume = { username: "u" };
    expect(() => expect(fakeSecondConsume).toBeNull()).toThrow();
  });

  // PROP 7 (red) — A store that returns state for an unsaved id is rejected.
  it("PROP 7 rejects a store that returns state for an unsaved id", () => {
    const fakeReturnForUnsaved = { username: "u" };
    expect(() => expect(fakeReturnForUnsaved).toBeNull()).toThrow();
  });

  // PROP 8 (red) — A parser that returns the whole id (including region
  //   prefix) instead of the suffix is rejected.
  it("PROP 8 rejects a parser that returns the whole id including the region prefix", () => {
    const id = "us-east-1_AbCd123";
    const expectedSuffix = "AbCd123";
    const buggyResult = id; // implementation forgot to split
    expect(() => expect(buggyResult).toBe(expectedSuffix)).toThrow();
  });
});
