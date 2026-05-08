import { describe, expect, it } from "vitest";
import { otp } from "./otp";

describe("otp", () => {
  it("generates a random 6-digit code by default", () => {
    expect(otp()()).toMatch(/^[0-9]{6}$/);
  });

  it("returns the configured Code when provided", () => {
    expect(otp({ Code: "123456" })()).toBe("123456");
  });

  it("prefers config.Code over process.env.CODE", () => {
    const original = process.env.CODE;
    process.env.CODE = "999999";
    try {
      expect(otp({ Code: "123456" })()).toBe("123456");
    } finally {
      process.env.CODE = original;
    }
  });

  it("falls back to process.env.CODE when no config provided", () => {
    const original = process.env.CODE;
    process.env.CODE = "654321";
    try {
      expect(otp()()).toBe("654321");
    } finally {
      process.env.CODE = original;
    }
  });
});
