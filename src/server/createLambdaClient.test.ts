import * as AWS from "aws-sdk";
import { describe, expect, it, vi } from "vitest";
import { createLambdaClient } from "./createLambdaClient";

describe("createLambdaClient", () => {
  it("forwards explicit credentials and region", () => {
    const ctor = vi.fn();
    createLambdaClient(
      {
        credentials: { accessKeyId: "AKIA", secretAccessKey: "secret" },
        region: "us-east-1",
      },
      ctor as unknown as typeof AWS.Lambda,
    );

    expect(ctor).toHaveBeenCalledWith({
      credentials: { accessKeyId: "AKIA", secretAccessKey: "secret" },
      region: "us-east-1",
    });
  });

  it("forwards endpoint when set", () => {
    const ctor = vi.fn();
    createLambdaClient(
      { endpoint: "http://localhost:3002", region: "us-east-1" },
      ctor as unknown as typeof AWS.Lambda,
    );

    expect(ctor).toHaveBeenCalledWith({
      endpoint: "http://localhost:3002",
      region: "us-east-1",
    });
  });

  describe("default credential chain", () => {
    // SDK falls through to env / instance-metadata / ~/.aws/credentials when
    // `credentials` is absent. Passing `null` or `undefined` would risk SDK
    // misbehavior, so the factory strips them.
    it("omits credentials key when config is undefined", () => {
      const ctor = vi.fn();
      createLambdaClient(undefined, ctor as unknown as typeof AWS.Lambda);

      const arg = ctor.mock.calls[0]?.[0] ?? {};
      expect(arg).not.toHaveProperty("credentials");
    });

    it("omits credentials key when config is empty object", () => {
      const ctor = vi.fn();
      createLambdaClient({}, ctor as unknown as typeof AWS.Lambda);

      const arg = ctor.mock.calls[0]?.[0] ?? {};
      expect(arg).not.toHaveProperty("credentials");
    });

    it("omits credentials key when credentials is null", () => {
      const ctor = vi.fn();
      createLambdaClient(
        { credentials: null as never, region: "us-east-1" },
        ctor as unknown as typeof AWS.Lambda,
      );

      const arg = ctor.mock.calls[0]?.[0] ?? {};
      expect(arg).not.toHaveProperty("credentials");
      expect(arg).toMatchObject({ region: "us-east-1" });
    });

    it("omits credentials key when credentials is undefined explicitly", () => {
      const ctor = vi.fn();
      createLambdaClient(
        { credentials: undefined, region: "us-east-1" },
        ctor as unknown as typeof AWS.Lambda,
      );

      const arg = ctor.mock.calls[0]?.[0] ?? {};
      expect(arg).not.toHaveProperty("credentials");
      expect(arg).toMatchObject({ region: "us-east-1" });
    });
  });

  it("returns an AWS.Lambda instance when called without a ctor override", () => {
    const client = createLambdaClient({ region: "us-east-1" });
    expect(client).toBeInstanceOf(AWS.Lambda);
  });
});
