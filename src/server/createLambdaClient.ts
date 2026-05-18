import * as AWS from "aws-sdk";

/**
 * Builds the AWS.Lambda client used for trigger invocations. Strips a
 * null/undefined `credentials` field so the SDK falls through to its default
 * credential chain (env, shared credentials file, ECS, EC2 instance metadata).
 *
 * SDK precedence:
 * https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-credentials-node.html
 */
export function createLambdaClient(
  config?: AWS.Lambda.ClientConfiguration,
  LambdaCtor: typeof AWS.Lambda = AWS.Lambda,
): AWS.Lambda {
  const { credentials, ...rest } = config ?? {};
  const args = credentials == null ? rest : { ...rest, credentials };
  return new LambdaCtor(args);
}
