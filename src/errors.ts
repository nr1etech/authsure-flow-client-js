/**
 * Error thrown by the AuthSureFlowClient.
 */
export class AuthSureFlowClientError extends Error {
  readonly name = 'AuthSureFlowClientError';
  constructor(
    message: string,
    public readonly cause?: unknown
  ) {
    super(message);
  }
}

/**
 * Returns true if the error is an AuthSureFlowClientError.
 *
 * @param e the error to check
 */
export function isAuthSureFlowClientError(
  e?: unknown
): e is AuthSureFlowClientError {
  return e instanceof Error && e.name === 'AuthSureFlowClientError';
}
