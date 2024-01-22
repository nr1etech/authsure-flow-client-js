import * as crypto from 'crypto';

/**
 * Generates a secure random 24 byte nonce.
 */
export function generateNonce(): string {
  return crypto.randomBytes(24).toString('base64url');
}

/**
 * Generates a secure random 96 byte, 128 character code verifier based on recommendations
 * in RFC 7636 which states code_verifier = high-entropy cryptographic random STRING using the
 * unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 * from Section 2.3 of [RFC3986], with a minimum length of 43 characters
 * and a maximum length of 128 characters.
 */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(96).toString('base64url');
}

/**
 * The calculated code verifier challenge.
 */
export interface CodeVerifierChallenge {
  readonly challenge: string;
  readonly method: string;
}

/**
 * Generates a code challenge based on the code verifier using the SHA-256 hash algorithm.
 */
export function generateCodeVerifierChallenge(
  codeVerifier: string
): CodeVerifierChallenge {
  return {
    challenge: crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url'),
    method: 'S256',
  };
}

/**
 * Generates a 128bit random state string.
 */
export function generateState(): string {
  return crypto.randomBytes(32).toString('base64url');
}
