import type {
  DeliveryMediumType,
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { v4 } from "uuid";
import {
  CodeMismatchError,
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { Services } from "../services";
import { srpPoolName, verifyClaimSignature } from "../services/srp";
import { verify as verifyTotp } from "../services/totp";
import {
  attributesToRecord,
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type RespondToAuthChallengeTarget = Target<
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse
>;

type RespondToAuthChallengeService = Pick<
  Services,
  | "clock"
  | "cognito"
  | "messages"
  | "otp"
  | "srpSessionStore"
  | "triggers"
  | "tokenGenerator"
>;

const sendSmsMfaChallenge = async (
  ctx: Parameters<RespondToAuthChallengeTarget>[0],
  req: RespondToAuthChallengeRequest,
  user: User,
  userPoolId: string,
  services: RespondToAuthChallengeService,
  saveUser: (u: User) => Promise<void>,
): Promise<RespondToAuthChallengeResponse> => {
  const smsMfaOption = user.MFAOptions?.find(
    (x): x is MFAOption & { DeliveryMedium: DeliveryMediumType } =>
      x.DeliveryMedium === "SMS",
  );
  if (!smsMfaOption) {
    throw new UnsupportedError("SMS_MFA without SMS MFAOption");
  }
  const deliveryDestination = attributeValue(
    smsMfaOption.AttributeName,
    user.Attributes,
  );
  if (!deliveryDestination) {
    throw new UnsupportedError(`SMS_MFA without ${smsMfaOption.AttributeName}`);
  }

  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    req.ClientId,
    userPoolId,
    user,
    code,
    req.ClientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await saveUser({ ...user, MFACode: code });

  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: deliveryDestination,
      USER_ID_FOR_SRP: user.Username,
    },
    Session: v4(),
  };
};

export const RespondToAuthChallenge =
  (services: RespondToAuthChallengeService): RespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const { clock, cognito, triggers, tokenGenerator } = services;

    if (!req.ChallengeResponses) {
      throw new InvalidParameterError(
        "Missing required parameter challenge responses",
      );
    }
    if (!req.ChallengeResponses.USERNAME) {
      throw new InvalidParameterError("Missing required parameter USERNAME");
    }
    if (!req.Session) {
      throw new InvalidParameterError("Missing required parameter Session");
    }

    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const userPoolClient = await cognito.getAppClient(ctx, req.ClientId);

    const user = await userPool.getUserByUsername(
      ctx,
      req.ChallengeResponses.USERNAME,
    );
    if (!user || !userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (req.ChallengeName === "SELECT_MFA_TYPE") {
      const answer = req.ChallengeResponses.ANSWER;
      if (answer === "SMS_MFA") {
        return sendSmsMfaChallenge(
          ctx,
          req,
          user,
          userPool.options.Id,
          services,
          (u) => userPool.saveUser(ctx, u),
        );
      }
      if (answer === "SOFTWARE_TOKEN_MFA") {
        return {
          ChallengeName: "SOFTWARE_TOKEN_MFA",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            ...(user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName
              ? {
                  FRIENDLY_DEVICE_NAME:
                    user.SoftwareTokenMfaConfiguration.FriendlyDeviceName,
                }
              : {}),
          },
          Session: v4(),
        };
      }
      throw new InvalidParameterError(
        "SELECT_MFA_TYPE requires ANSWER of SMS_MFA or SOFTWARE_TOKEN_MFA",
      );
    }

    if (req.ChallengeName === "SMS_MFA") {
      if (user.MFACode !== req.ChallengeResponses.SMS_MFA_CODE) {
        throw new CodeMismatchError();
      }

      await userPool.saveUser(ctx, {
        ...user,
        MFACode: undefined,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      const code = req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE;
      const secret = user.SoftwareTokenMfaConfiguration?.Secret;
      if (
        !code ||
        !secret ||
        !user.SoftwareTokenMfaConfiguration?.Verified ||
        !verifyTotp(secret, code)
      ) {
        throw new CodeMismatchError();
      }
      await userPool.saveUser(ctx, {
        ...user,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      if (!req.ChallengeResponses.NEW_PASSWORD) {
        throw new InvalidParameterError(
          "Missing required parameter NEW_PASSWORD",
        );
      }

      // TODO: validate the password?
      await userPool.saveUser(ctx, {
        ...user,
        Password: req.ChallengeResponses.NEW_PASSWORD,
        UserLastModifiedDate: clock.get(),
        UserStatus: "CONFIRMED",
      });
    } else if (req.ChallengeName === "PASSWORD_VERIFIER") {
      if (user.Password === undefined) {
        throw new InvalidPasswordError();
      }

      // SRP-6a verification: rebuild the shared secret from the session state
      // we stashed in initiateAuth, recompute the expected claim signature,
      // and compare in constant time to what the client sent. A mismatch
      // (including a wrong password) collapses to NotAuthorizedError.
      const sessionState = services.srpSessionStore.consume(req.Session ?? "");
      if (!sessionState || sessionState.username !== user.Username) {
        throw new NotAuthorizedError();
      }
      const claimSignatureBase64 =
        req.ChallengeResponses.PASSWORD_CLAIM_SIGNATURE;
      const claimSecretBlockBase64 =
        req.ChallengeResponses.PASSWORD_CLAIM_SECRET_BLOCK;
      const timestamp = req.ChallengeResponses.TIMESTAMP;
      if (!claimSignatureBase64 || !claimSecretBlockBase64 || !timestamp) {
        throw new InvalidParameterError(
          "Missing required PASSWORD_VERIFIER ChallengeResponses",
        );
      }
      const ok = verifyClaimSignature({
        poolName: srpPoolName(userPool.options.Id),
        username: user.Username,
        password: user.Password,
        salt: sessionState.salt,
        A: sessionState.A,
        B: sessionState.B,
        b: sessionState.b,
        secretBlock: sessionState.secretBlock,
        timestamp,
        claimSecretBlockBase64,
        claimSignatureBase64,
      });
      if (!ok) {
        throw new NotAuthorizedError();
      }

      // Check if MFA is required
      if (
        (userPool.options.MfaConfiguration === "OPTIONAL" &&
          ((user.MFAOptions ?? []).length > 0 ||
            (user.UserMFASettingList ?? []).length > 0)) ||
        userPool.options.MfaConfiguration === "ON"
      ) {
        return {
          ChallengeName:
            user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA"
              ? "SOFTWARE_TOKEN_MFA"
              : "SMS_MFA",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
          } as RespondToAuthChallengeResponse["ChallengeParameters"],
          Session: v4(),
        };
      }

      if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
        // amazon-cognito-identity-js calls JSON.parse on both userAttributes and
        // requiredAttributes when it receives a NEW_PASSWORD_REQUIRED challenge,
        // so both fields must be present and valid JSON. Omitting userAttributes
        // makes the SDK call JSON.parse(undefined) and throw
        // SyntaxError: "undefined" is not valid JSON.
        //
        // SDK:  https://github.com/aws-amplify/amplify-js/blob/5166dc40b49763dd9ec17eb153e3ce08b66b191b/packages/amazon-cognito-identity-js/src/CognitoUser.js#L471-L496
        // AWS docs (RespondToAuthChallenge): https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html#API_RespondToAuthChallenge_ResponseSyntax
        //
        // The initiateAuth NEW_PASSWORD_REQUIRED path already includes
        // userAttributes (see src/targets/initiateAuth.ts:newPasswordChallenge);
        // this branch mirrors that shape so SRP and non-SRP flows agree.
        return {
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            requiredAttributes: JSON.stringify([]),
            userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
          } as RespondToAuthChallengeResponse["ChallengeParameters"],
          Session: v4(),
        };
      }
    } else if (req.ChallengeName === "MFA_SETUP") {
      // MFA_SETUP is returned when a user needs to set up TOTP MFA
      // The client calls AssociateSoftwareToken + VerifySoftwareToken
      // then responds to MFA_SETUP. For the emulator, just mark setup complete.
      if (!req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE) {
        throw new InvalidParameterError(
          "Missing required parameter SOFTWARE_TOKEN_MFA_CODE",
        );
      }

      const mfaSettingList = user.UserMFASettingList ?? [];
      if (!mfaSettingList.includes("SOFTWARE_TOKEN_MFA")) {
        mfaSettingList.push("SOFTWARE_TOKEN_MFA");
      }

      await userPool.saveUser(ctx, {
        ...user,
        UserMFASettingList: mfaSettingList,
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "CUSTOM_CHALLENGE") {
      if (!triggers.enabled("VerifyAuthChallengeResponse")) {
        throw new UnsupportedError(
          "CUSTOM_CHALLENGE requires VerifyAuthChallengeResponse trigger",
        );
      }

      const verifyResult = await triggers.verifyAuthChallengeResponse(ctx, {
        clientId: req.ClientId,
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
        challengeAnswer: req.ChallengeResponses.ANSWER ?? "",
        clientMetadata: req.ClientMetadata,
      });

      if (!verifyResult.answerCorrect) {
        throw new CodeMismatchError();
      }
    } else {
      throw new UnsupportedError(
        `respondToAuthChallenge with ChallengeName=${req.ChallengeName}`,
      );
    }

    if (triggers.enabled("PostAuthentication")) {
      await triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
      });
    }

    const userGroups = await userPool.listUserGroupMembership(ctx, user);

    return {
      ChallengeParameters: {},
      AuthenticationResult: await tokenGenerator.generate(
        ctx,
        user,
        userGroups,
        userPoolClient,
        req.ClientMetadata,
        "Authentication",
      ),
    };
  };
