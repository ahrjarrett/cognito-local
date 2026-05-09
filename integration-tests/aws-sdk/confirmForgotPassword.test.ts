import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

describe(
  "CognitoIdentityServiceProvider.confirmForgotPassword",
  withCognitoSdk((Cognito, { messageDelivery }) => {
    it("rejects a wrong code with real-Cognito phrasing", async () => {
      const client = Cognito();

      const pool = await client.createUserPool({ PoolName: "test" }).promise();
      const userPoolId = pool.UserPool?.Id as string;

      const upc = await client
        .createUserPoolClient({
          UserPoolId: userPoolId,
          ClientName: "test",
        })
        .promise();
      const clientId = upc.UserPoolClient?.ClientId as string;

      await client
        .signUp({
          ClientId: clientId,
          Username: "abc",
          Password: "def",
          UserAttributes: [{ Name: "email", Value: "example@example.com" }],
        })
        .promise();

      await client
        .adminConfirmSignUp({ UserPoolId: userPoolId, Username: "abc" })
        .promise();

      await client
        .forgotPassword({ ClientId: clientId, Username: "abc" })
        .promise();

      await expect(
        client
          .confirmForgotPassword({
            ClientId: clientId,
            Username: "abc",
            ConfirmationCode: "000000",
            Password: "newPassword",
          })
          .promise(),
      ).rejects.toMatchObject({
        code: "CodeMismatchException",
        message: "Invalid verification code provided, please try again.",
      });
    });

    it("resets the password when the code matches", async () => {
      const client = Cognito();

      const pool = await client.createUserPool({ PoolName: "test" }).promise();
      const userPoolId = pool.UserPool?.Id as string;

      const upc = await client
        .createUserPoolClient({
          UserPoolId: userPoolId,
          ClientName: "test",
        })
        .promise();
      const clientId = upc.UserPoolClient?.ClientId as string;

      await client
        .signUp({
          ClientId: clientId,
          Username: "abc",
          Password: "originalPassword",
          UserAttributes: [{ Name: "email", Value: "example@example.com" }],
        })
        .promise();

      await client
        .adminConfirmSignUp({ UserPoolId: userPoolId, Username: "abc" })
        .promise();

      await client
        .forgotPassword({ ClientId: clientId, Username: "abc" })
        .promise();

      const code = messageDelivery().collectedMessages.at(-1)?.message?.__code;
      expect(code).toBeDefined();

      await client
        .confirmForgotPassword({
          ClientId: clientId,
          Username: "abc",
          ConfirmationCode: code as string,
          Password: "newPassword",
        })
        .promise();

      // The new password should now authenticate.
      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: "abc",
            PASSWORD: "newPassword",
          },
        })
        .promise();

      expect(auth.AuthenticationResult).toEqual({
        AccessToken: expect.any(String),
        IdToken: expect.any(String),
        RefreshToken: expect.any(String),
      });
    });
  }),
);
