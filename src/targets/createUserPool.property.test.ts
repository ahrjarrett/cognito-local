import type {
  CreateUserPoolRequest,
  PasswordPolicyType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import * as fc from "fast-check";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { CognitoService } from "../services";
import { CreateUserPool, type CreateUserPoolTarget } from "./createUserPool";

// Property-based tests for the CreateUserPool target.
//
// Invariants encoded here come from official AWS sources. Each property
// quotes the relevant doc text directly so the contract stays visible in
// the test file (not just in the PR description). Citations:
//
//   [CUP]  CreateUserPool API reference
//          https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html
//   [PPT]  PasswordPolicyType reference
//          https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_PasswordPolicyType.html
//   [SDK]  aws-sdk v2 TypeScript type signatures
//          node_modules/aws-sdk/clients/cognitoidentityserviceprovider.d.ts
//
// Local-emulator-specific invariants (Id/Arn format, clock-based timestamps)
// reference src/targets/createUserPool.ts with line numbers.

// PoolName, per [CUP] request parameters:
//   > "PoolName -- A friendly name for your user pool.
//   >  Type: String
//   >  Length Constraints: Minimum length of 1. Maximum length of 128.
//   >  Pattern: [\w\s+=,.@-]+
//   >  Required: Yes"
const poolNameArbitrary: fc.Arbitrary<string> = fc
  .stringMatching(/^[\w\s+=,.@-]{1,128}$/)
  .filter((s) => s.length >= 1 && s.length <= 128);

// PasswordPolicyType, per [PPT]:
//   > "MinimumLength -- ... This value can't be less than 6.
//   >  Type: Integer. Valid Range: Minimum value of 6. Maximum value of 99."
//   > "RequireLowercase / RequireNumbers / RequireSymbols / RequireUppercase --
//   >  Type: Boolean. Required: No."
//   > "TemporaryPasswordValidityDays -- ... Defaults to 7. If you submit a
//   >  value of 0, Amazon Cognito treats it as a null value and sets
//   >  TemporaryPasswordValidityDays to its default value.
//   >  Type: Integer. Valid Range: Minimum value of 0. Maximum value of 365."
//
// PasswordHistorySize (0..24 per [PPT]) is omitted: it is not present in the
// pinned aws-sdk@2.x PasswordPolicyType type [SDK], so generating it would
// fail typechecking against the bundled SDK.
const passwordPolicyArbitrary: fc.Arbitrary<PasswordPolicyType> = fc.record(
  {
    MinimumLength: fc.integer({ min: 6, max: 99 }),
    RequireUppercase: fc.boolean(),
    RequireLowercase: fc.boolean(),
    RequireNumbers: fc.boolean(),
    RequireSymbols: fc.boolean(),
    TemporaryPasswordValidityDays: fc.integer({ min: 0, max: 365 }),
  },
  { requiredKeys: [] },
);

const localPoolIdRegex = /^local_[0-9A-Za-z]{8}$/;
const localPoolArnRegex =
  /^arn:aws:cognito-idp:local:local:userpool\/local_[0-9A-Za-z]{8}$/;

describe("CreateUserPool target — property tests", () => {
  let createUserPool: CreateUserPoolTarget;
  let mockCognitoService: MockedObject<CognitoService>;
  let clock: ClockFake;

  beforeEach(() => {
    clock = new ClockFake(new Date());
    mockCognitoService = newMockCognitoService(newMockUserPoolService());
    createUserPool = CreateUserPool({ cognito: mockCognitoService, clock });
    mockCognitoService.createUserPool.mockImplementation(async (_ctx, pool) =>
      TDB.userPool(pool),
    );
  });

  // PROP 1 — PoolName is preserved verbatim onto UserPool.Name.
  //
  // [CUP] CreateUserPool response: "Name" is part of UserPoolType. The
  //   sample response in the API reference echoes the request's PoolName
  //   ("my-test-user-pool") back as UserPool.Name unchanged.
  // Local impl: createUserPool.ts:98 assigns `Name: req.PoolName` directly.
  it("preserves PoolName as UserPool.Name", async () => {
    await fc.assert(
      fc.asyncProperty(poolNameArbitrary, async (poolName) => {
        mockCognitoService.createUserPool.mockClear();
        await createUserPool(TestContext, { PoolName: poolName });
        expect(mockCognitoService.createUserPool).toHaveBeenCalledTimes(1);
        const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
        expect(pool.Name).toBe(poolName);
      }),
    );
  });

  // PROP 2 — Generated Id matches /^local_[0-9A-Za-z]{8}$/.
  //
  // [CUP] User pool Ids in real AWS take the shape "<region>_<random>" --
  //   the sample response shows "Id": "us-east-1_EXAMPLE". The local
  //   emulator substitutes "local" for the region and an 8-char short-uuid
  //   from a 62-char alphanumeric alphabet for the suffix.
  // Local impl: createUserPool.ts:15-17 (alphabet definition) and :82
  //   (`${REGION}_${generator.new().slice(0, 8)}` -> "local_<8>").
  it("generates an Id matching local_<8 alnum>", async () => {
    await fc.assert(
      fc.asyncProperty(poolNameArbitrary, async (poolName) => {
        mockCognitoService.createUserPool.mockClear();
        await createUserPool(TestContext, { PoolName: poolName });
        const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
        expect(pool.Id).toMatch(localPoolIdRegex);
      }),
    );
  });

  // PROP 3 — Arn matches the documented ARN shape and contains the pool's Id.
  //
  // [CUP] Sample response shows:
  //   > "Arn": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_EXAMPLE"
  //   > "Id":  "us-east-1_EXAMPLE"
  // i.e. the Arn is `arn:aws:cognito-idp:<region>:<account>:userpool/<Id>`,
  //   and its suffix after the last "/" must equal Id.
  // Local impl: createUserPool.ts:87 builds
  //   `arn:aws:cognito-idp:${REGION}:${ACCOUNT_ID}:userpool/${userPoolId}`
  //   with REGION=ACCOUNT_ID="local".
  // We assert (a) the regex shape and (b) Arn ends with the same Id we returned.
  it("generates an Arn that matches the userpool ARN shape and ends with Id", async () => {
    await fc.assert(
      fc.asyncProperty(poolNameArbitrary, async (poolName) => {
        mockCognitoService.createUserPool.mockClear();
        await createUserPool(TestContext, { PoolName: poolName });
        const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
        expect(pool.Arn).toMatch(localPoolArnRegex);
        expect(pool.Arn?.endsWith(`/${pool.Id}`)).toBe(true);
      }),
    );
  });

  // PROP 4 — At creation time, CreationDate === LastModifiedDate.
  //
  // [CUP] Sample response shows both timestamps as the same instant:
  //   > "CreationDate":     1689721665.239
  //   > "LastModifiedDate": 1689721665.239
  // This is the only timestamp evidence in the API reference, but it's
  //   reproducible: a freshly-created pool has not been modified yet, so
  //   the two values must agree at creation.
  // Local impl: createUserPool.ts:81 reads `clock.get()` once into `now`
  //   and assigns it to both CreationDate (line 89) and LastModifiedDate
  //   (line 96).
  it("sets CreationDate equal to LastModifiedDate at creation", async () => {
    await fc.assert(
      fc.asyncProperty(poolNameArbitrary, async (poolName) => {
        mockCognitoService.createUserPool.mockClear();
        await createUserPool(TestContext, { PoolName: poolName });
        const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
        expect(pool.CreationDate).toEqual(pool.LastModifiedDate);
      }),
    );
  });

  // PROP 5 — Policies object is passed through unchanged.
  //
  // [CUP] Policies appears identically in both the request body and the
  //   UserPool response object (PasswordPolicy + SignInPolicy). The sample
  //   request and response in the API reference show identical Policies
  //   on both sides. The PasswordPolicyType reference [PPT] states the
  //   type is "a request and response parameter of CreateUserPool",
  //   confirming the symmetric contract.
  // Local impl: createUserPool.ts:99 passes `req.Policies` through unchanged.
  // We generate any spec-conformant PasswordPolicy and require deep equality.
  it("passes Policies through to the storage layer unchanged", async () => {
    await fc.assert(
      fc.asyncProperty(
        poolNameArbitrary,
        passwordPolicyArbitrary,
        async (poolName, passwordPolicy) => {
          mockCognitoService.createUserPool.mockClear();
          const policies: CreateUserPoolRequest["Policies"] = {
            PasswordPolicy: passwordPolicy,
          };
          await createUserPool(TestContext, {
            PoolName: poolName,
            Policies: policies,
          });
          const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
          expect(pool.Policies).toEqual(policies);
        },
      ),
    );
  });

  // PROP 6 — Each call produces a fresh, distinct Id.
  //
  // [CUP] Id is the primary identifier for a user pool throughout the API:
  //   DescribeUserPool, DeleteUserPool, UpdateUserPool, and every per-pool
  //   operation key off it. The implicit contract is that each successful
  //   CreateUserPool returns a fresh Id distinct from any prior pool's Id.
  // Local impl: createUserPool.ts:15-17 defines a short-uuid generator over
  //   a 62-char alphanumeric alphabet; :82 takes 8 chars per call. The 62^8
  //   space (~218 trillion) makes accidental collision astronomical.
  // This property guards against a regression where the generator becomes
  //   deterministic (e.g. a hardcoded seed, or `generator` moved to module
  //   scope and the slice length reduced).
  it("produces a unique Id for each call", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(poolNameArbitrary, { minLength: 2, maxLength: 8 }),
        async (poolNames) => {
          mockCognitoService.createUserPool.mockClear();
          for (const poolName of poolNames) {
            await createUserPool(TestContext, { PoolName: poolName });
          }
          const ids = mockCognitoService.createUserPool.mock.calls.map(
            ([, pool]) => pool.Id,
          );
          expect(new Set(ids).size).toBe(ids.length);
        },
      ),
    );
  });

  // PROP 7 — Schema attribute names that are not default attributes are
  //          rewritten with a "custom:" prefix; defaults are not.
  //
  // [CUP] The CreateUserPool sample request adds a custom attribute named
  //   "mydev"; the sample response echoes it back as
  //   > "Name": "dev:custom:mydev"
  //   (the additional "dev:" prefix is because DeveloperOnlyAttribute was true
  //   in the request -- without that flag the stored name is "custom:mydev").
  // SchemaAttributeType defaults observed in the same sample response and
  //   documented in the Cognito Developer Guide: DeveloperOnlyAttribute
  //   defaults to false, Mutable to true, Required to false.
  // Local impl: createSchemaAttributes in createUserPool.ts:34-76 splits
  //   the request schema into overrides (names that match an AWS default
  //   attribute) and customs (everything else, prefixed with "custom:"
  //   at line 59 and defaulted at lines 61-63).
  // We sample names that are guaranteed not to collide with default
  //   attribute names by giving each a "novel_" prefix.
  it("prefixes non-default schema attribute names with custom:", async () => {
    await fc.assert(
      fc.asyncProperty(
        poolNameArbitrary,
        fc
          .stringMatching(/^[A-Za-z][A-Za-z0-9_]{0,16}$/)
          .map((s) => `novel_${s}`),
        async (poolName, attrName) => {
          mockCognitoService.createUserPool.mockClear();
          await createUserPool(TestContext, {
            PoolName: poolName,
            Schema: [{ Name: attrName, AttributeDataType: "String" }],
          });
          const [, pool] = mockCognitoService.createUserPool.mock.calls[0]!;
          const attr = (pool.SchemaAttributes ?? []).find(
            (a) => a.Name === `custom:${attrName}`,
          );
          expect(attr).toBeDefined();
          expect(attr?.AttributeDataType).toBe("String");
          // Per AWS schema attribute defaults observed in DescribeUserPool:
          //   DeveloperOnlyAttribute defaults false; Mutable defaults true; Required defaults false.
          // Local impl assigns these defaults when omitted (createUserPool.ts:61-63).
          expect(attr?.DeveloperOnlyAttribute).toBe(false);
          expect(attr?.Mutable).toBe(true);
          expect(attr?.Required).toBe(false);
        },
      ),
    );
  });

  // PROP 8 — TemporaryPasswordValidityDays in [0, 365] is accepted without error.
  //
  // [PPT] TemporaryPasswordValidityDays:
  //   > "Type: Integer. Valid Range: Minimum value of 0. Maximum value of 365.
  //   >  Required: No."
  //   > "Defaults to 7. If you submit a value of 0, Amazon Cognito treats
  //   >  it as a null value and sets TemporaryPasswordValidityDays to its
  //   >  default value."
  // Implication: every integer in [0, 365] is a spec-conformant input and
  //   CreateUserPool must accept it (in particular, 0 is documented as a
  //   "treated as null" sentinel, not an error).
  // The local impl is a pass-through, so this property guards against a
  //   future overzealous validator that rejects values in the documented
  //   range -- a known footgun when re-implementing AWS validation manually.
  it("accepts every documented TemporaryPasswordValidityDays value", async () => {
    await fc.assert(
      fc.asyncProperty(
        poolNameArbitrary,
        fc.integer({ min: 0, max: 365 }),
        async (poolName, days) => {
          mockCognitoService.createUserPool.mockClear();
          await expect(
            createUserPool(TestContext, {
              PoolName: poolName,
              Policies: {
                PasswordPolicy: { TemporaryPasswordValidityDays: days },
              },
            }),
          ).resolves.toBeDefined();
        },
      ),
    );
  });
});

// Self-checks (red side of red-green) — each property above must catch the
// kind of regression it's meant to catch. We feed the *same* assertion logic
// a hardcoded, fabricated bad output that violates the invariant under test,
// and verify with vitest that the assertion throws. These tests are pure
// proofs of discriminating power; they do not exercise CreateUserPool itself.
//
// If you change an invariant above, update the matching red case below so
// the "bad" fixture continues to violate exactly that invariant. If you
// later weaken an assertion (e.g. broaden a regex), the corresponding red
// test will start passing on what was previously a violating input -- that
// is the signal to investigate whether the invariant is still meaningful.
describe("CreateUserPool property invariants — self-checks (red)", () => {
  // PROP 1 (red) — A pool whose Name doesn't match the input PoolName is rejected.
  it("PROP 1 rejects a pool with a mismatched Name", () => {
    const inputPoolName = "expected-pool-name";
    const fakePool = { Name: "WRONG-NAME" };
    expect(() => expect(fakePool.Name).toBe(inputPoolName)).toThrow();
  });

  // PROP 2 (red) — An Id that doesn't match local_<8 alnum> is rejected.
  it("PROP 2 rejects an Id that doesn't match local_<8 alnum>", () => {
    const fakePool = { Id: "us-east-1_NotLocalFmt" };
    expect(() => expect(fakePool.Id).toMatch(localPoolIdRegex)).toThrow();
  });

  // PROP 3 (red) — Arn shape mismatch and Id-suffix mismatch are both rejected.
  it("PROP 3 rejects a malformed Arn and an Arn that doesn't end with Id", () => {
    const fakePoolBadShape = {
      Id: "local_AAAAAAAA",
      Arn: "arn:aws:s3:::not-a-userpool",
    };
    expect(() =>
      expect(fakePoolBadShape.Arn).toMatch(localPoolArnRegex),
    ).toThrow();

    const fakePoolIdMismatch = {
      Id: "local_AAAAAAAA",
      Arn: "arn:aws:cognito-idp:local:local:userpool/local_BBBBBBBB",
    };
    expect(() =>
      expect(fakePoolIdMismatch.Arn.endsWith(`/${fakePoolIdMismatch.Id}`)).toBe(
        true,
      ),
    ).toThrow();
  });

  // PROP 4 (red) — Differing CreationDate / LastModifiedDate is rejected.
  it("PROP 4 rejects a pool whose CreationDate differs from LastModifiedDate", () => {
    const fakePool = {
      CreationDate: new Date("2020-01-01T00:00:00.000Z"),
      LastModifiedDate: new Date("2020-01-01T00:00:00.001Z"),
    };
    expect(() =>
      expect(fakePool.CreationDate).toEqual(fakePool.LastModifiedDate),
    ).toThrow();
  });

  // PROP 5 (red) — A mutated Policies object on the way out is rejected.
  it("PROP 5 rejects a mutated Policies object", () => {
    const inputPolicies = {
      PasswordPolicy: {
        MinimumLength: 8,
        RequireUppercase: true,
        RequireLowercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
        TemporaryPasswordValidityDays: 7,
      },
    };
    const fakePool = {
      Policies: {
        PasswordPolicy: { ...inputPolicies.PasswordPolicy, MinimumLength: 99 },
      },
    };
    expect(() => expect(fakePool.Policies).toEqual(inputPolicies)).toThrow();
  });

  // PROP 6 (red) — Two identical Ids cause Set-size to drop below array length.
  it("PROP 6 rejects an Id collision", () => {
    const ids = ["local_AAAAAAAA", "local_AAAAAAAA", "local_BBBBBBBB"];
    expect(() => expect(new Set(ids).size).toBe(ids.length)).toThrow();
  });

  // PROP 7 (red) — A custom attribute stored without the "custom:" prefix is rejected.
  it("PROP 7 rejects a custom attribute missing its custom: prefix", () => {
    const attrName = "novel_foo";
    const fakeSchemaAttributes = [
      // Bug: stored as bare attribute name instead of "custom:novel_foo"
      { Name: "novel_foo", AttributeDataType: "String" },
    ];
    const found = fakeSchemaAttributes.find(
      (a) => a.Name === `custom:${attrName}`,
    );
    expect(() => expect(found).toBeDefined()).toThrow();
  });

  // PROP 8 (red) — A buggy implementation that throws on a valid input is detected.
  // The green property uses `await expect(...).resolves.toBeDefined()`. If the
  // call rejects instead of resolving, that assertion itself rejects.
  it("PROP 8 rejects an implementation that throws on a documented input", async () => {
    const buggyCall = Promise.reject(new Error("rejected by buggy impl"));
    await expect(expect(buggyCall).resolves.toBeDefined()).rejects.toThrow();
  });
});
