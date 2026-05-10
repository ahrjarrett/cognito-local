import type {
  AdminUpdateUserAttributesRequest,
  AdminUpdateUserAttributesResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Messages, Services, UserPoolService } from "../services";
import { USER_POOL_AWS_DEFAULTS } from "../services/cognitoService";
import type { Context } from "../services/context";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import {
  attributesAppend,
  hasUnverifiedContactAttributes,
  splitImmediateAndDelayedAttributes,
  type User,
  validateEmailAttribute,
  validatePermittedAttributeChanges,
  validatePhoneNumberAttribute,
} from "../services/userPoolService";
import type { Target } from "./Target";

const sendAttributeVerificationCode = async (
  ctx: Context,
  userPool: UserPoolService,
  user: User,
  messages: Messages,
  req: AdminUpdateUserAttributesRequest,
  code: string,
) => {
  const deliveryDetails = selectAppropriateDeliveryMethod(
    userPool.options.AutoVerifiedAttributes ?? [],
    user,
  );
  if (!deliveryDetails) {
    // TODO: I don't know what the real error message should be for this
    throw new InvalidParameterError(
      "User has no attribute matching desired auto verified attributes",
    );
  }

  await messages.deliver(
    ctx,
    "UpdateUserAttribute",
    null,
    userPool.options.Id,
    user,
    code,
    req.ClientMetadata,
    deliveryDetails,
  );
};

export type AdminUpdateUserAttributesTarget = Target<
  AdminUpdateUserAttributesRequest,
  AdminUpdateUserAttributesResponse
>;

type AdminUpdateUserAttributesServices = Pick<
  Services,
  "clock" | "cognito" | "otp" | "messages"
>;

export const AdminUpdateUserAttributes =
  ({
    clock,
    cognito,
    otp,
    messages,
  }: AdminUpdateUserAttributesServices): AdminUpdateUserAttributesTarget =>
  async (ctx, req) => {
    validatePhoneNumberAttribute(req.UserAttributes);
    validateEmailAttribute(req.UserAttributes);

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new NotAuthorizedError();
    }

    const permittedAttributeChanges = validatePermittedAttributeChanges(
      req.UserAttributes,
      // if the user pool doesn't have any SchemaAttributes it was probably created manually
      // or before we started explicitly saving the defaults. Fallback on the AWS defaults in
      // this case, otherwise checks against the schema for default attributes like email will
      // fail.
      userPool.options.SchemaAttributes ??
        USER_POOL_AWS_DEFAULTS.SchemaAttributes ??
        [],
    );

    const [immediateAttributes, delayedAttributes] =
      splitImmediateAndDelayedAttributes(
        permittedAttributeChanges,
        userPool.options.UserAttributeUpdateSettings
          ?.AttributesRequireVerificationBeforeUpdate,
      );

    const updatedUser: User = {
      ...user,
      Attributes: attributesAppend(user.Attributes, ...immediateAttributes),
      UserLastModifiedDate: clock.get(),
      UnverifiedAttributeChanges:
        delayedAttributes.length > 0 ? delayedAttributes : undefined,
    };

    await userPool.saveUser(ctx, updatedUser);

    // deliberately only check the affected user attributes, not the combined attributes
    // e.g. a user with email_verified=false that you don't touch the email attributes won't get notified
    if (
      userPool.options.AutoVerifiedAttributes?.length &&
      (hasUnverifiedContactAttributes(immediateAttributes) ||
        hasUnverifiedContactAttributes(delayedAttributes))
    ) {
      const code = otp();

      await userPool.saveUser(ctx, {
        ...updatedUser,
        AttributeVerificationCode: code,
      });

      await sendAttributeVerificationCode(
        ctx,
        userPool,
        updatedUser,
        messages,
        req,
        code,
      );
    }

    return {};
  };
