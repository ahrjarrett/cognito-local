import { describe, expect, it } from "vitest";
import {
  newMockDataStore,
  newMockDataStoreFactory,
} from "../__tests__/mockDataStore";
import { TestContext } from "../__tests__/testContext";
import { DefaultConfig, loadConfig } from "./config";

describe("loadConfig", () => {
  it("returns the default config if no config exists", async () => {
    const config = await loadConfig(TestContext, newMockDataStoreFactory());

    expect(config).toEqual(DefaultConfig);
  });

  it("merges the defaults with any existing config", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      TriggerFunctions: {
        CustomMessage: "custom-config",
      },
      UserPoolDefaults: {
        MFAOptions: "OPTIONAL",
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      TriggerFunctions: {
        CustomMessage: "custom-config",
      },
      UserPoolDefaults: {
        // new field
        MFAOptions: "OPTIONAL",
        // field from defaults
        UsernameAttributes: ["email"],
      },
    });
  });

  it("can unset a property when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: null,
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: null,
      },
    });
  });

  it("overwrites arrays when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: ["phone_number"],
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: ["phone_number"],
      },
    });
  });

  it("can set an arrays to empty when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: [],
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: [],
      },
    });
  });

  describe("LambdaClient defaults", () => {
    // No hardcoded fake creds. Lets the AWS SDK default chain (env, instance
    // metadata, ~/.aws/credentials) work when invoking real AWS Lambdas.
    it("does not seed fake credentials into DefaultConfig", () => {
      expect(DefaultConfig.LambdaClient).not.toHaveProperty("credentials");
    });

    it("preserves a partial LambdaClient config without leaking default creds", async () => {
      const ds = newMockDataStore();
      const mockDataStoreFactory = newMockDataStoreFactory(ds);

      ds.getRoot.mockResolvedValue({
        LambdaClient: { region: "us-east-1" },
      });

      const config = await loadConfig(TestContext, mockDataStoreFactory);

      expect(config.LambdaClient).not.toHaveProperty("credentials");
      expect(config.LambdaClient).toMatchObject({ region: "us-east-1" });
    });

    it("respects explicit credentials in user config", async () => {
      const ds = newMockDataStore();
      const mockDataStoreFactory = newMockDataStoreFactory(ds);

      ds.getRoot.mockResolvedValue({
        LambdaClient: {
          credentials: { accessKeyId: "AKIA", secretAccessKey: "secret" },
          region: "us-east-1",
        },
      });

      const config = await loadConfig(TestContext, mockDataStoreFactory);

      expect(config.LambdaClient).toEqual({
        credentials: { accessKeyId: "AKIA", secretAccessKey: "secret" },
        region: "us-east-1",
      });
    });

    it("respects explicit null credentials in user config (opt-in to default chain)", async () => {
      const ds = newMockDataStore();
      const mockDataStoreFactory = newMockDataStoreFactory(ds);

      ds.getRoot.mockResolvedValue({
        LambdaClient: { credentials: null, region: "us-east-1" },
      });

      const config = await loadConfig(TestContext, mockDataStoreFactory);

      expect(config.LambdaClient.credentials).toBeNull();
    });
  });
});
