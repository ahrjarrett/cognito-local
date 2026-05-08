export interface OtpConfig {
  Code?: string;
}

export const otp =
  (config: OtpConfig = {}) =>
  (): string =>
    config.Code ??
    process.env.CODE ??
    Math.floor(Math.random() * 999999)
      .toString()
      .padStart(6, "0");
