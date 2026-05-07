import express from "express";
import * as jwt from "jsonwebtoken";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { appClient } from "../__tests__/testDataBuilder";
import PublicKey from "../keys/cognitoLocal.public.json";
import type { Services } from "../services";
import { DefaultConfig } from "./config";
import { createOAuth2Router } from "./oauth2Router";

function buildApp(services: Services) {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(createOAuth2Router(services));
  return app;
}

describe("POST /oauth2/token — client_credentials grant", () => {
  const USER_POOL_ID = "us-east-1_TestPool";
  const CLIENT_ID = "testclientid123";
  const CLIENT_SECRET = "supersecret";

  const seededClient = appClient({
    ClientId: CLIENT_ID,
    ClientSecret: CLIENT_SECRET,
    UserPoolId: USER_POOL_ID,
    AllowedOAuthFlows: ["client_credentials"],
    AllowedOAuthScopes: ["api/full"],
  });

  let services: Services;

  beforeEach(() => {
    const mockCognito = newMockCognitoService();
    vi.mocked(mockCognito.getAppClient).mockResolvedValue(seededClient);

    services = {
      authorizationCodeStore: {
        save: vi.fn(),
        lookup: vi.fn(),
        consume: vi.fn(),
      },
      clock: new ClockFake(new Date("2025-01-01T00:00:00Z")),
      cognito: mockCognito,
      config: {
        ...DefaultConfig,
        TokenConfig: {
          IssuerDomain: "https://cognito-idp.us-east-1.amazonaws.com",
        },
      },
      messages: {} as any,
      otp: vi.fn(),
      tokenGenerator: {} as any,
      triggers: {} as any,
    };
  });

  it("returns 200 with access_token for valid client_credentials request", async () => {
    const app = buildApp(services);

    const res = await request(app).post("/oauth2/token").type("form").send({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: "api/full",
    });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.token_type).toBe("Bearer");

    // Verify the token against the public key. ClockFake is in the past so
    // ignoreExpiration lets us check structure without wall-clock drift.
    const decoded = jwt.verify(res.body.access_token, PublicKey.pem, {
      algorithms: ["RS256"],
      ignoreExpiration: true,
    }) as jwt.JwtPayload;

    expect(decoded.iss).toBe(
      `https://cognito-idp.us-east-1.amazonaws.com/${USER_POOL_ID}`,
    );
    expect(decoded.token_use).toBe("access");
    expect(decoded.sub).toBe(CLIENT_ID);

    // kid lives in the JWT header, not the payload
    const header = JSON.parse(
      Buffer.from(res.body.access_token.split(".")[0], "base64url").toString(),
    );
    expect(header.kid).toBe("CognitoLocal");
  });

  it("returns 401 invalid_client for wrong client secret", async () => {
    const app = buildApp(services);

    const res = await request(app).post("/oauth2/token").type("form").send({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: "wrongsecret",
      scope: "api/full",
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid_client");
  });
});
