import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Messages, UserPoolService } from "../services";
import {
  attribute,
  attributesAppend,
  attributeValue,
} from "../services/userPoolService";
import {
  AdminUpdateUserAttributes,
  type AdminUpdateUserAttributesTarget,
} from "./adminUpdateUserAttributes";

const validValueFor = (attr: string) => {
  if (attr === "phone_number") return "+61400000000";
  if (attr === "email") return "example@example.com";
  return "new value";
};

describe("AdminUpdateUserAttributes target", () => {
  let adminUpdateUserAttributes: AdminUpdateUserAttributesTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let clock: ClockFake;
  let mockMessages: MockedObject<Messages>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    clock = new ClockFake(new Date());
    mockMessages = newMockMessages();
    adminUpdateUserAttributes = AdminUpdateUserAttributes({
      clock,
      cognito: newMockCognitoService(mockUserPoolService),
      messages: mockMessages,
      otp: () => "123456",
    });
  });

  it("throws if the user doesn't exist", async () => {
    await expect(
      adminUpdateUserAttributes(TestContext, {
        ClientMetadata: {
          client: "metadata",
        },
        UserPoolId: "test",
        UserAttributes: [{ Name: "custom:example", Value: "1" }],
        Username: "abc",
      }),
    ).rejects.toEqual(new NotAuthorizedError());
  });

  it("saves the updated attributes on the user", async () => {
    const user = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.options.SchemaAttributes = [
      {
        Name: "custom:example",
        Mutable: true,
      },
    ];

    await adminUpdateUserAttributes(TestContext, {
      ClientMetadata: {
        client: "metadata",
      },
      UserPoolId: "test",
      UserAttributes: [attribute("custom:example", "1")],
      Username: "abc",
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      Attributes: attributesAppend(
        user.Attributes,
        attribute("custom:example", "1"),
      ),
      UserLastModifiedDate: clock.get(),
    });
  });

  describe.each`
    desc                                                         | attribute                  | expectedError
    ${"an attribute not in the schema"}                          | ${"custom:missing"}        | ${"user.custom:missing: Attribute does not exist in the schema."}
    ${"an attribute which isn't mutable in the schema"}          | ${"custom:immutable"}      | ${"user.custom:immutable: Attribute cannot be updated. (changing an immutable attribute)"}
    ${"email_verified without an email attribute"}               | ${"email_verified"}        | ${"Email is required to verify/un-verify an email"}
    ${"phone_number_verified without an phone_number attribute"} | ${"phone_number_verified"} | ${"Phone Number is required to verify/un-verify a phone number"}
  `("req.UserAttributes contains $desc", ({ attribute, expectedError }) => {
    beforeEach(() => {
      mockUserPoolService.options.SchemaAttributes = [
        {
          Name: "email_verified",
          Mutable: true,
        },
        {
          Name: "phone_number_verified",
          Mutable: true,
        },
        {
          Name: "custom:immutable",
          Mutable: false,
        },
      ];
    });

    it("throws an invalid parameter error", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(TDB.user());

      await expect(
        adminUpdateUserAttributes(TestContext, {
          ClientMetadata: {
            client: "metadata",
          },
          UserPoolId: "test",
          UserAttributes: [{ Name: attribute, Value: "1" }],
          Username: "abc",
        }),
      ).rejects.toEqual(new InvalidParameterError(expectedError));
    });
  });

  describe.each([
    "0400000000",
    "+1NotAPhoNum",
    "+ThisIsDefinitelyNotAPhoneNum",
    "+",
    "+0123456789",
    "1234567890",
  ])("when phone_number is %j", (phoneNumber) => {
    it("throws InvalidParameterError with the real-Cognito message", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(TDB.user());

      const promise = adminUpdateUserAttributes(TestContext, {
        UserPoolId: "test",
        UserAttributes: [{ Name: "phone_number", Value: phoneNumber }],
        Username: "abc",
      });

      await expect(promise).rejects.toBeInstanceOf(InvalidParameterError);
      await expect(promise).rejects.toThrow("Invalid phone number format.");
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });
  });

  describe.each([
    "test+roger@@qbdvision.com",
    "test14+roger@qbdvision.com!!!!",
    "no-at-sign",
    "missing-tld@example",
    "@no-local.com",
    "trailing-dot@example.",
    "spaces in@local.com",
  ])("when email is %j", (email) => {
    it("throws InvalidParameterError with the real-Cognito message", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(TDB.user());

      const promise = adminUpdateUserAttributes(TestContext, {
        UserPoolId: "test",
        UserAttributes: [{ Name: "email", Value: email }],
        Username: "abc",
      });

      await expect(promise).rejects.toBeInstanceOf(InvalidParameterError);
      await expect(promise).rejects.toThrow("Invalid email address format.");
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });
  });

  describe.each(["email", "phone_number"])(
    "%s is in req.UserAttributes without the relevant verified attribute",
    (attr) => {
      it(`sets the ${attr}_verified attribute to false`, async () => {
        const user = TDB.user();
        const value = validValueFor(attr);

        mockUserPoolService.getUserByUsername.mockResolvedValue(user);

        await adminUpdateUserAttributes(TestContext, {
          ClientMetadata: {
            client: "metadata",
          },
          UserPoolId: "test",
          UserAttributes: [attribute(attr, value)],
          Username: "abc",
        });

        expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
          ...user,
          Attributes: attributesAppend(
            user.Attributes,
            attribute(attr, value),
            attribute(`${attr}_verified`, "false"),
          ),
          UserLastModifiedDate: clock.get(),
        });
      });
    },
  );

  describe("user pool has auto verified attributes enabled", () => {
    beforeEach(() => {
      mockUserPoolService.options.AutoVerifiedAttributes = ["email"];
    });

    describe.each`
      attributes
      ${["email"]}
      ${["phone_number"]}
      ${["email", "phone_number"]}
    `("when $attributes is unverified", ({ attributes }) => {
      describe("the verification status was not affected by the update", () => {
        it("does not deliver a OTP code to the user", async () => {
          const user = TDB.user({
            Attributes: attributes.map((attr: string) =>
              attribute(`${attr}_verified`, "false"),
            ),
          });

          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          mockUserPoolService.options.SchemaAttributes = [
            { Name: "example", Mutable: true },
          ];

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: [attribute("example", "1")],
            Username: "abc",
          });

          expect(mockMessages.deliver).not.toHaveBeenCalled();
        });
      });

      describe("the verification status changed because of the update", () => {
        it("throws if the resulting user has no attribute matching AutoVerifiedAttributes", async () => {
          // AutoVerifiedAttributes is ["email"] in this describe block, so the
          // verification destination must be an email. If the post-update user
          // doesn't end up with one, there's nowhere to send the code.
          const willHaveEmailAfterUpdate = attributes.includes("email");

          const user = TDB.user({
            Attributes: [],
          });

          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          const promise = adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: attributes.map((attr: string) =>
              attribute(attr, validValueFor(attr)),
            ),
            Username: "abc",
          });

          if (willHaveEmailAfterUpdate) {
            await expect(promise).resolves.toEqual({});
          } else {
            await expect(promise).rejects.toEqual(
              new InvalidParameterError(
                "User has no attribute matching desired auto verified attributes",
              ),
            );
          }
        });

        it("delivers a OTP code to the user with the post-update attributes", async () => {
          const user = TDB.user();
          const updates = attributes.map((attr: string) =>
            attribute(attr, validValueFor(attr)),
          );

          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: updates,
            Username: "abc",
          });

          // Real Cognito invokes CustomMessage_UpdateUserAttribute *after*
          // applying the attribute change to the user record (the default,
          // when AttributesRequireVerificationBeforeUpdate is empty), so the
          // lambda's request.userAttributes reflects the post-update state
          // and the verification code is delivered to the new email/phone.
          const updatedUser = {
            ...user,
            Attributes: attributesAppend(
              user.Attributes,
              ...updates,
              ...attributes.map((attr: string) =>
                attribute(`${attr}_verified`, "false"),
              ),
            ),
            UserLastModifiedDate: clock.get(),
            UnverifiedAttributeChanges: undefined,
          };

          expect(mockMessages.deliver).toHaveBeenCalledWith(
            TestContext,
            "UpdateUserAttribute",
            null,
            "test",
            updatedUser,
            "123456",
            { client: "metadata" },
            {
              AttributeName: "email",
              DeliveryMedium: "EMAIL",
              Destination: attributeValue("email", updatedUser.Attributes),
            },
          );

          expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
            TestContext,
            expect.objectContaining({
              AttributeVerificationCode: "123456",
            }),
          );
        });
      });
    });

    describe.each(["email", "phone_number"] as const)(
      "when %s is in AttributesRequireVerificationBeforeUpdate",
      (attr) => {
        it("keeps the original value active and tracks the new value on UnverifiedAttributeChanges", async () => {
          const user = TDB.user();

          mockUserPoolService.options.UserAttributeUpdateSettings = {
            AttributesRequireVerificationBeforeUpdate: [attr],
          };
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: [attribute(attr, validValueFor(attr))],
            Username: "abc",
          });

          // Per the Cognito Developer Guide ("Verifying updates to email
          // addresses and phone numbers"), when verification is required the
          // user can sign in and receive messages with the original attribute
          // value until they verify the new value. The new value sits on
          // UnverifiedAttributeChanges, not on Attributes.
          const updatedUser = {
            ...user,
            UnverifiedAttributeChanges: [
              attribute(attr, validValueFor(attr)),
              attribute(`${attr}_verified`, "false"),
            ],
            UserLastModifiedDate: clock.get(),
          };

          expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
            TestContext,
            updatedUser,
          );
        });
      },
    );

    describe.each(["email", "phone_number"] as const)(
      "when %s is not in AttributesRequireVerificationBeforeUpdate",
      (attr) => {
        it("saves the updated attribute value immediately", async () => {
          const user = TDB.user();

          mockUserPoolService.options.UserAttributeUpdateSettings = {
            AttributesRequireVerificationBeforeUpdate: [],
          };
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: [attribute(attr, validValueFor(attr))],
            Username: "abc",
          });

          const updatedUser = {
            ...user,
            Attributes: attributesAppend(
              user.Attributes,
              attribute(attr, validValueFor(attr)),
              attribute(`${attr}_verified`, "false"),
            ),
            UserLastModifiedDate: clock.get(),
            UnverifiedAttributeChanges: undefined,
          };

          expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
            TestContext,
            updatedUser,
          );
        });
      },
    );
  });

  describe("user pool does not have auto verified attributes", () => {
    beforeEach(() => {
      mockUserPoolService.options.AutoVerifiedAttributes = [];
    });

    describe.each`
      attributes
      ${["email"]}
      ${["phone_number"]}
      ${["email", "phone_number"]}
    `("when $attributes is unverified", ({ attributes }) => {
      describe("the verification status was not affected by the update", () => {
        it("does not deliver a OTP code to the user", async () => {
          const user = TDB.user({
            Attributes: attributes.map((attr: string) =>
              attribute(`${attr}_verified`, "false"),
            ),
          });

          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          mockUserPoolService.options.SchemaAttributes = [
            { Name: "example", Mutable: true },
          ];

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: [attribute("example", "1")],
            Username: "abc",
          });

          expect(mockMessages.deliver).not.toHaveBeenCalled();
        });
      });

      describe("the verification status changed because of the update", () => {
        it("does not deliver a OTP code to the user", async () => {
          const user = TDB.user();

          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          await adminUpdateUserAttributes(TestContext, {
            ClientMetadata: {
              client: "metadata",
            },
            UserPoolId: "test",
            UserAttributes: attributes.map((attr: string) =>
              attribute(attr, validValueFor(attr)),
            ),
            Username: "abc",
          });

          expect(mockMessages.deliver).not.toHaveBeenCalled();
        });
      });
    });
  });
});
