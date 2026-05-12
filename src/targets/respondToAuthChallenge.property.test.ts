import * as fc from "fast-check";
import {
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { Messages, Triggers, UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import {
  RespondToAuthChallenge,
  type RespondToAuthChallengeTarget,
} from "./respondToAuthChallenge";

// Property-based tests for the PASSWORD_VERIFIER → NEW_PASSWORD_REQUIRED
// response shape (the path that fires when an SRP-authenticating client
// reaches a user whose UserStatus is FORCE_CHANGE_PASSWORD).
//
// Invariants encoded here come from the AWS SDK source that consumes this
// challenge and the Cognito API reference. Each property cites the source
// directly so the contract stays visible in the test file.
//
//   [SDK]  amazon-cognito-identity-js/src/CognitoUser.js, authenticateUserInternal
//          https://github.com/aws-amplify/amplify-js/blob/5166dc40b49763dd9ec17eb153e3ce08b66b191b/packages/amazon-cognito-identity-js/src/CognitoUser.js#L471-L496
//
//          Inside the NEW_PASSWORD_REQUIRED branch, the SDK unconditionally calls
//
//            userAttributes      = JSON.parse(ChallengeParameters.userAttributes);
//            rawRequiredAttrs    = JSON.parse(ChallengeParameters.requiredAttributes);
//
//          so both fields must be present and must be a valid JSON string.
//          Omitting userAttributes coerces JSON.parse(undefined) to the string
//          "undefined", which throws SyntaxError: "undefined" is not valid JSON.
//
//   [RTA]  RespondToAuthChallenge API reference
//          https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html
//
//          ChallengeName: "For users who are required to change their passwords
//          after successful first login. Respond to this challenge with NEW_PASSWORD
//          and any required attributes that Amazon Cognito returned in the
//          requiredAttributes parameter." The companion NEW_PASSWORD_REQUIRED
//          response on InitiateAuth (src/targets/initiateAuth.ts:newPasswordChallenge)
//          already includes both requiredAttributes and userAttributes — this file
//          asserts that the SRP path in respondToAuthChallenge.ts agrees.

// We're testing response *shape*, not SRP math. The real SRP verifier is
// covered by src/services/srp.property.test.ts. Stubbing
// verifyClaimSignature lets every generated case reach the
// FORCE_CHANGE_PASSWORD branch without needing to construct a valid claim.
//
// srpPoolName is also re-exported from this module; we keep the real
// implementation since the FORCE_CHANGE_PASSWORD path doesn't call it but
// other branches in respondToAuthChallenge.ts do, and we don't want to
// break those if test layout changes.
vi.mock("../services/srp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../services/srp")>();
  return {
    ...actual,
    verifyClaimSignature: vi.fn(() => true),
  };
});

const attributeNameArbitrary = fc.oneof(
  fc.constantFrom(
    "sub",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
    "given_name",
    "family_name",
    "name",
    "preferred_username",
    "address",
    "birthdate",
    "gender",
    "locale",
    "middle_name",
    "nickname",
    "picture",
    "profile",
    "updated_at",
    "website",
    "zoneinfo",
  ),
  fc.stringMatching(/^custom:[A-Za-z][A-Za-z0-9_]{0,32}$/),
);

// Generate AttributeListType values: arrays of {Name, Value} pairs with
// distinct Name keys (Cognito enforces uniqueness per attribute name).
const attributesArbitrary = fc.uniqueArray(
  fc.record({
    Name: attributeNameArbitrary,
    Value: fc.string({ minLength: 0, maxLength: 64 }),
  }),
  { selector: (a) => a.Name, minLength: 0, maxLength: 12 },
);

describe("RespondToAuthChallenge — PASSWORD_VERIFIER → NEW_PASSWORD_REQUIRED shape", () => {
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let clock: ClockFake;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    clock = new ClockFake(new Date());
    mockTokenGenerator = newMockTokenGenerator();
    mockTriggers = newMockTriggers();
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
  });

  // Build a target with a session-store whose consume() returns state matching
  // the user under test, so the inline `sessionState.username !== user.Username`
  // check at respondToAuthChallenge.ts:201 passes. verifyClaimSignature is
  // stubbed at the module level (vi.mock above), so the exact SRP numbers
  // don't matter — only the username equality check does.
  const buildTarget = (
    user: ReturnType<typeof TDB.user>,
  ): RespondToAuthChallengeTarget => {
    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);
    return RespondToAuthChallenge({
      clock,
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      srpSessionStore: {
        save: vi.fn(),
        consume: vi.fn().mockReturnValue({
          username: user.Username,
          password: user.Password,
          salt: Buffer.alloc(16),
          A: 1n,
          B: 1n,
          b: 1n,
          secretBlock: Buffer.alloc(64),
        }),
      },
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });
  };

  const runPasswordVerifier = async (
    attributes: { Name: string; Value: string }[],
  ) => {
    const user = TDB.user({
      Attributes: attributes,
      Password: "TempPassword123!",
      UserStatus: "FORCE_CHANGE_PASSWORD",
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const target = buildTarget(user);
    return target(TestContext, {
      ClientId: userPoolClient.ClientId,
      ChallengeName: "PASSWORD_VERIFIER",
      ChallengeResponses: {
        USERNAME: user.Username,
        PASSWORD_CLAIM_SIGNATURE: "stub-signature",
        PASSWORD_CLAIM_SECRET_BLOCK: Buffer.alloc(64).toString("base64"),
        TIMESTAMP: "Wed Jan 1 00:00:00 UTC 2020",
      },
      Session: "session-id",
    });
  };

  // PROP 1 — Response always advertises a NEW_PASSWORD_REQUIRED challenge
  //          when the user is in FORCE_CHANGE_PASSWORD.
  //
  // [RTA] The NEW_PASSWORD_REQUIRED challenge is the documented way Cognito
  //   signals "user must pick a permanent password before tokens are issued."
  // Local impl: respondToAuthChallenge.ts FORCE_CHANGE_PASSWORD branch.
  it("returns ChallengeName=NEW_PASSWORD_REQUIRED for FORCE_CHANGE_PASSWORD users", async () => {
    await fc.assert(
      fc.asyncProperty(attributesArbitrary, async (attributes) => {
        const response = await runPasswordVerifier(attributes);
        expect(response.ChallengeName).toBe("NEW_PASSWORD_REQUIRED");
      }),
    );
  });

  // PROP 2 — ChallengeParameters.userAttributes is always a valid JSON string.
  //
  // This is the regression guard. [SDK] calls JSON.parse on this field
  // unconditionally; if it is undefined or non-string, the SDK throws
  // SyntaxError: "undefined" is not valid JSON before the user ever sees the
  // password-change screen. The property holds for *any* user.Attributes
  // value, including the empty array.
  it("returns ChallengeParameters.userAttributes that parses as valid JSON", async () => {
    await fc.assert(
      fc.asyncProperty(attributesArbitrary, async (attributes) => {
        const response = await runPasswordVerifier(attributes);
        const raw = response.ChallengeParameters?.userAttributes;
        expect(typeof raw).toBe("string");
        // Exercises the exact code path the SDK exercises:
        // [SDK] userAttributes = JSON.parse(ChallengeParameters.userAttributes)
        expect(() => JSON.parse(raw as string)).not.toThrow();
      }),
    );
  });

  // PROP 3 — ChallengeParameters.requiredAttributes is also a valid JSON string.
  //
  // Same SDK code path on the next line: rawRequiredAttributes = JSON.parse(...).
  // We assert it as well so any future change that drops *either* field is caught.
  it("returns ChallengeParameters.requiredAttributes that parses as valid JSON", async () => {
    await fc.assert(
      fc.asyncProperty(attributesArbitrary, async (attributes) => {
        const response = await runPasswordVerifier(attributes);
        const raw = response.ChallengeParameters?.requiredAttributes;
        expect(typeof raw).toBe("string");
        expect(() => JSON.parse(raw as string)).not.toThrow();
      }),
    );
  });

  // PROP 4 — Round-trip: JSON.parse(userAttributes) reflects every (Name, Value)
  //          pair from user.Attributes.
  //
  // The newPasswordChallenge helper in initiateAuth.ts encodes the user's
  // AttributeListType through attributesToRecord — i.e. as a flat
  // Record<string, string>. We assert the SRP path follows the same shape so
  // both NEW_PASSWORD_REQUIRED return sites stay interchangeable.
  it("encodes every (Name, Value) pair from user.Attributes into userAttributes", async () => {
    await fc.assert(
      fc.asyncProperty(attributesArbitrary, async (attributes) => {
        const response = await runPasswordVerifier(attributes);
        const decoded: Record<string, string> = JSON.parse(
          response.ChallengeParameters?.userAttributes as string,
        );
        // attributesToRecord drops attributes whose Name or Value is missing;
        // our arbitrary generates both, so every input pair must appear.
        for (const { Name, Value } of attributes) {
          if (Name && Value) {
            expect(decoded[Name]).toBe(Value);
          }
        }
      }),
    );
  });
});

// Self-checks (red side of red-green): each property above must catch the
// kind of regression it's meant to catch. We feed the same assertion logic a
// hardcoded, fabricated bad output that violates the invariant under test
// and verify with vitest that the assertion throws. These tests are pure
// proofs of discriminating power; they do not exercise RespondToAuthChallenge.
//
// PROP 2 (red) is the most important: it is the exact failure mode we just
// fixed — ChallengeParameters.userAttributes was `undefined`, so the SDK
// called JSON.parse(undefined) and threw "undefined" is not valid JSON.
describe("RespondToAuthChallenge property invariants — self-checks (red)", () => {
  // PROP 1 (red) — A non-NEW_PASSWORD_REQUIRED ChallengeName for a FORCE_CHANGE_PASSWORD
  // user is rejected.
  it("PROP 1 rejects a response that returns the wrong ChallengeName", () => {
    const fakeResponse = { ChallengeName: "SMS_MFA" };
    expect(() =>
      expect(fakeResponse.ChallengeName).toBe("NEW_PASSWORD_REQUIRED"),
    ).toThrow();
  });

  // PROP 2 (red) — A missing userAttributes field (the exact pre-fix bug) is rejected.
  it("PROP 2 rejects a ChallengeParameters with userAttributes=undefined", () => {
    const fakeChallengeParameters: Record<string, string | undefined> = {
      USER_ID_FOR_SRP: "u",
      requiredAttributes: "[]",
      // userAttributes intentionally omitted — reproduces the pre-fix bug
    };
    expect(() =>
      expect(typeof fakeChallengeParameters.userAttributes).toBe("string"),
    ).toThrow();
    // And the downstream JSON.parse that the SDK runs on this value:
    expect(() =>
      JSON.parse(fakeChallengeParameters.userAttributes as string),
    ).toThrow(SyntaxError);
  });

  // PROP 3 (red) — A missing requiredAttributes field is rejected.
  it("PROP 3 rejects a ChallengeParameters with requiredAttributes=undefined", () => {
    const fakeChallengeParameters: Record<string, string | undefined> = {
      USER_ID_FOR_SRP: "u",
      userAttributes: "{}",
      // requiredAttributes intentionally omitted
    };
    expect(() =>
      expect(typeof fakeChallengeParameters.requiredAttributes).toBe("string"),
    ).toThrow();
  });

  // PROP 4 (red) — A userAttributes payload that omits an input pair is rejected.
  it("PROP 4 rejects a userAttributes payload that drops an input pair", () => {
    const inputAttributes = [
      { Name: "email", Value: "a@b.com" },
      { Name: "sub", Value: "abc" },
    ];
    // Bug: "sub" got dropped on the way out.
    const decoded: Record<string, string> = JSON.parse(
      JSON.stringify({ email: "a@b.com" }),
    );
    expect(() => {
      for (const { Name, Value } of inputAttributes) {
        if (Name && Value) {
          expect(decoded[Name]).toBe(Value);
        }
      }
    }).toThrow();
  });
});
