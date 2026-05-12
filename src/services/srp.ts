import {
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

// AWS Cognito uses the 3072-bit MODP group from RFC 5054 Appendix A.
// This N and g pair are baked into amazon-cognito-identity-js and all
// AWS-published SRP clients; they're public constants, not secrets.
const N_HEX_RAW =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
  "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
  "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
  "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
  "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

export const N = BigInt(`0x${N_HEX_RAW}`);
export const G = 2n;
export const N_BYTE_LENGTH = 384; // 3072 bits

// HKDF info field used by AWS Cognito SRP. The trailing 0x01 byte is the
// counter that HKDF-Expand prepends for the first (and only) output block.
const HKDF_INFO = Buffer.from("Caldera Derived Key", "utf-8");
const HKDF_LEN = 16;

/**
 * Pad a BigInt to its unsigned big-endian hex representation, matching
 * amazon-cognito-identity-js's `padHex`:
 *   - even number of hex characters (zero-pad the high nibble if odd)
 *   - prefix "00" if the high nibble has its high bit set, so the value
 *     is unambiguously interpreted as unsigned by Java's BigInteger.
 *
 * Used everywhere SRP values feed into a hash. We do **not** pad to N's full
 * byte length here — the client doesn't either, and the hash bytes must agree
 * on both ends.
 */
export function padHex(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  } else if ("89abcdef".includes(hex[0])) {
    hex = `00${hex}`;
  }
  return hex;
}

/** Convenience: padHex(value) decoded as bytes. */
export function padHexBytes(value: bigint): Buffer {
  return Buffer.from(padHex(value), "hex");
}

// SRP-6a multiplier k = H(PAD(N) | PAD(g)).
// Computed once at module load.
const K_HEX = createHash("sha256")
  .update(Buffer.from(padHex(N) + padHex(G), "hex"))
  .digest("hex");
export const K = BigInt(`0x${K_HEX}`);

/** Modular exponentiation for BigInts. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  let b = base % mod;
  if (b < 0n) b += mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/**
 * Compute the SRP password "x" value used by AWS Cognito:
 *   inner = SHA256(`${poolName}${username}:${password}`)
 *   x     = SHA256(PAD(salt, 16) || inner)
 *
 * `poolName` is the portion of the user pool id after the `_` (e.g.
 * `us-east-1_AbCd123` → `AbCd123`). `username` is the value returned to
 * the client as USER_ID_FOR_SRP — for Cognito with `UsernameAttributes:
 * ["email"]` that's the sub UUID, otherwise the raw username.
 */
export function computeX(
  poolName: string,
  username: string,
  password: string,
  saltBytes: Buffer,
): bigint {
  const inner = createHash("sha256")
    .update(Buffer.from(`${poolName}${username}:${password}`, "utf-8"))
    .digest();
  const xHex = createHash("sha256")
    .update(Buffer.concat([padSalt(saltBytes), inner]))
    .digest("hex");
  return BigInt(`0x${xHex}`);
}

/** Pad SRP salt to 16 bytes (left-pad with zeros). */
function padSalt(salt: Buffer): Buffer {
  if (salt.length >= 16) return salt;
  return Buffer.concat([Buffer.alloc(16 - salt.length, 0), salt]);
}

/** Compute SRP password verifier v = g^x mod N. */
export function computeVerifier(x: bigint): bigint {
  return modPow(G, x, N);
}

/**
 * Server-side InitiateAuth step: given an existing user's verifier v, return a
 * fresh (b, B) pair suitable for the PASSWORD_VERIFIER challenge.
 *
 * `b` is the server private exponent (kept in the session store, never sent
 * to the client). `B = (k*v + g^b) mod N`. We reject `b === 0` and `B mod N
 * === 0` per SRP-6a and re-roll.
 */
export function generateServerKeypair(v: bigint): { b: bigint; B: bigint } {
  for (let attempt = 0; attempt < 8; attempt++) {
    const bBytes = randomBytes(N_BYTE_LENGTH);
    const b = BigInt(`0x${bBytes.toString("hex")}`) % N;
    if (b === 0n) continue;
    const B = (K * v + modPow(G, b, N)) % N;
    if (B % N !== 0n) return { b, B };
  }
  // Astronomically unlikely; throw rather than return weak keys.
  throw new Error("Failed to generate SRP server keypair");
}

/**
 * Validate a client's PASSWORD_CLAIM_SIGNATURE against the stored SRP state.
 * Returns true iff the signature matches the password we hold for `username`.
 *
 * `secretBlock` must be the exact bytes we sent the client in the InitiateAuth
 * response. The client echoes it back base64-encoded in
 * PASSWORD_CLAIM_SECRET_BLOCK; we verify the echo before validating the
 * signature, otherwise a replay of a signature from a different session would
 * appear to validate.
 */
export function verifyClaimSignature(args: {
  poolName: string;
  username: string;
  password: string;
  salt: Buffer;
  A: bigint;
  B: bigint;
  b: bigint;
  secretBlock: Buffer;
  timestamp: string;
  claimSecretBlockBase64: string;
  claimSignatureBase64: string;
}): boolean {
  const {
    poolName,
    username,
    password,
    salt,
    A,
    B,
    b,
    secretBlock,
    timestamp,
    claimSecretBlockBase64,
    claimSignatureBase64,
  } = args;

  // Reject degenerate A per SRP-6a.
  if (A % N === 0n) return false;

  // The echoed secret block must match exactly. If it doesn't, the client is
  // either replaying a different session or our state is stale — either way
  // we can't trust the signature.
  let echoedSecretBlock: Buffer;
  try {
    echoedSecretBlock = Buffer.from(claimSecretBlockBase64, "base64");
  } catch {
    return false;
  }
  if (
    echoedSecretBlock.length !== secretBlock.length ||
    !timingSafeEqual(echoedSecretBlock, secretBlock)
  ) {
    return false;
  }

  const u = BigInt(
    `0x${createHash("sha256")
      .update(Buffer.concat([padHexBytes(A), padHexBytes(B)]))
      .digest("hex")}`,
  );
  if (u === 0n) return false;

  const x = computeX(poolName, username, password, salt);
  const v = computeVerifier(x);

  // S = (A * v^u)^b mod N — server-side derivation of the shared secret.
  const S = modPow((A * modPow(v, u, N)) % N, b, N);

  // K_auth = HKDF-SHA256(salt=PAD(u), IKM=PAD(S), info="Caldera Derived Key", L=16)
  const kAuth = Buffer.from(
    hkdfSync("sha256", padHexBytes(S), padHexBytes(u), HKDF_INFO, HKDF_LEN),
  );

  // Expected claim = HMAC-SHA256(K_auth, poolName || username || secretBlock || timestamp)
  const expected = createHmac("sha256", kAuth)
    .update(Buffer.from(poolName, "utf-8"))
    .update(Buffer.from(username, "utf-8"))
    .update(secretBlock)
    .update(Buffer.from(timestamp, "utf-8"))
    .digest();

  let provided: Buffer;
  try {
    provided = Buffer.from(claimSignatureBase64, "base64");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

/**
 * Extract the SRP pool name from a Cognito user pool id.
 * `us-east-1_AbCd123` → `AbCd123`. If no underscore is present the full id
 * is returned (matches amazon-cognito-identity-js).
 */
export function srpPoolName(userPoolId: string): string {
  const underscore = userPoolId.indexOf("_");
  return underscore === -1 ? userPoolId : userPoolId.slice(underscore + 1);
}
