import {
  createRemoteJWKSet,
  FlattenedJWSInput,
  JWSHeaderParameters,
  JWTPayload,
  jwtVerify,
  KeyLike,
  decodeJwt,
} from 'jose';

type Jwks = (
  protectedHeader?: JWSHeaderParameters,
  token?: FlattenedJWSInput
) => Promise<KeyLike>;

/**
 * Provider provided data.
 */
interface ProviderData {
  /**
   * Email address if provided.
   */
  email?: string;
  /**
   * External authentication provider ID.
   */
  externalId?: string;
  /**
   * User's name provided by the external authentication provider.
   */
  name: string;
  /**
   * User's given name provided by the external authentication provider.
   */
  givenName?: string;
  /**
   * User's family name provided by the external authentication provider.
   */
  familyName?: string;
  /**
   * Date provider data was obtained.
   */
  asOfDate: number;

  /**
   * Any other provider data.
   */
  [propName: string]: unknown;
}

interface DecodedRawIdToken extends JWTPayload {
  scope?: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  idp?: string;
  provider_id?: string;
  provider_type?: string;
  provider_login_hint?: string;
  provider_data?: ProviderData;
  nonce?: string;
}

/**
 * Timestamps for a token.
 */
export interface TokenTimestamps {
  /**
   * JWT Not Before
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
   */
  nbf: number;
  /**
   * JWT Expiration Time
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
   */
  exp: number;
  /**
   * JWT Issued At
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}
   */
  iat: number;
}

/**
 * Checks if an exp timestamp is expired.
 *
 * @param exp the expiration timestamp
 * @param bufferSeconds the number of seconds to subtract from the expiration timestamp
 */
export function isExpired(exp: number, bufferSeconds?: number) {
  return Date.now() > (exp - (bufferSeconds ?? 0)) * 1000;
}

/**
 * Checks if a token is expired.
 *
 * @param token the token to check
 * @param bufferSeconds the number of seconds to subtract from the expiration timestamp
 */
export function isTokenExpired(token: TokenTimestamps, bufferSeconds?: number) {
  return isExpired(token.exp, bufferSeconds);
}

/**
 * Decoded ID Token.
 */
export interface DecodedIdToken extends TokenTimestamps {
  /**
   * JWT Issuer
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
   */
  iss: string;
  /**
   * JWT Subject
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
   */
  sub: string;
  /**
   * JWT Audience
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
   */
  aud: string[];
  /**
   * JWT ID
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
   */
  jti: string;
  /**
   * Email address if one is provided.
   */
  email?: string;
  /**
   * Name of user.
   */
  name: string;
  /**
   * Given name of the user.
   */
  givenName?: string;
  /**
   * Family name of the user.
   */
  familyName?: string;
  /**
   * Identify provider used.
   */
  idp?: string;
  /**
   * Identify provider ID.
   */
  providerId?: string;
  /**
   * Identify provider type.
   */
  providerType?: string;
  /**
   * Identify provider login hint.
   */
  providerLoginHint?: string;
  /**
   * Provider provided data.
   */
  providerData?: ProviderData;
  /**
   * Nonce used.
   */
  nonce?: string;
  /** Any other JWT Claim Set member. */
  [propName: string]: unknown;
}

function rawToDecodedIdToken(
  payload: DecodedRawIdToken
): DecodedIdToken | null {
  if (payload.name === undefined || payload.name === null) {
    return null;
  }
  if (payload.aud === undefined || payload.aud === null) {
    return null;
  }
  if (payload.iss === undefined || payload.iss === null) {
    return null;
  }
  if (payload.sub === undefined || payload.sub === null) {
    return null;
  }
  if (payload.jti === undefined || payload.jti === null) {
    return null;
  }
  if (payload.nbf === undefined || payload.nbf === null) {
    return null;
  }
  if (payload.exp === undefined || payload.exp === null) {
    return null;
  }
  if (payload.iat === undefined || payload.iat === null) {
    return null;
  }
  return {
    iss: payload.iss,
    sub: payload.sub,
    aud: Array.isArray(payload.aud) ? payload.aud : [payload.aud],
    jti: payload.jti,
    nbf: payload.nbf,
    exp: payload.exp,
    iat: payload.iat,
    email: payload.email,
    name: payload.name,
    givenName: payload.given_name,
    familyName: payload.family_name,
    idp: payload.idp,
    providerId: payload.provider_id,
    providerType: payload.provider_type,
    providerLoginHint: payload.provider_login_hint,
    providerData: payload.provider_data,
    nonce: payload.nonce,
  };
}

interface DecodedRawAccessToken extends JWTPayload {
  scope?: string;
  client_id?: string;
}

export interface DecodedAccessToken extends TokenTimestamps {
  /**
   * JWT Issuer
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
   */
  iss: string;
  /**
   * JWT Subject
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
   */
  sub?: string;
  /**
   * JWT Audience
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
   */
  aud: string[];
  /**
   * JWT ID
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
   */
  jti: string;
  /**
   * Scopes allowed.
   */
  scopes: string[];
  /**
   * Client ID.
   */
  clientId: string;
  /**
   * Any other JWT Claim Set member.
   */
  [propName: string]: unknown;
}

function rawToDecodedAccessToken(
  payload: DecodedRawAccessToken
): DecodedAccessToken | null {
  if (payload.client_id === undefined || payload.client_id === null) {
    return null;
  }
  if (payload.aud === undefined || payload.aud === null) {
    return null;
  }
  if (payload.issue === undefined || payload.issue === null) {
    return null;
  }
  if (payload.jti === undefined || payload.jti === null) {
    return null;
  }
  if (payload.nbf === undefined || payload.nbf === null) {
    return null;
  }
  if (payload.exp === undefined || payload.exp === null) {
    return null;
  }
  if (payload.iat === undefined || payload.iat === null) {
    return null;
  }
  return {
    iss: payload.iss!,
    sub: payload.sub,
    aud: Array.isArray(payload.aud) ? payload.aud : [payload.aud],
    jti: payload.jti,
    nbf: payload.nbf,
    exp: payload.exp,
    iat: payload.iat,
    scopes: payload.scope?.split(' ') ?? [],
    clientId: payload.client_id,
  };
}

/**
 * Decodes an access token without verifying it.
 *
 * @param accessToken the access token to decode
 */
export function decodeAccessToken(
  accessToken: string
): DecodedAccessToken | null {
  try {
    const payload = decodeJwt(accessToken) as unknown as DecodedRawAccessToken;
    return rawToDecodedAccessToken(payload);
  } catch (err) {
    return null;
  }
}

/**
 * Properties for the JWT verifier.
 */
export interface JwtVerifierProps {
  readonly jwksUri: string;
}

/**
 * Properties for verifying an ID token.
 */
export interface VerifyIdTokenProps {
  readonly idToken: string;
  readonly clientId: string;
  readonly issuer: string;
}

/**
 * Properties for verifying an access token.
 */
export interface VerifyAccessTokenProps {
  readonly accessToken: string;
  readonly audience: string;
  readonly issuer: string;
}

/**
 * Used to handle JWT verification handling JWKS caching.
 */
export class JwtVerifier {
  public readonly jwksUri: string;
  protected readonly jwks: Jwks;

  constructor(props: JwtVerifierProps) {
    this.jwksUri = props.jwksUri;
    // eslint-disable-next-line node/no-unsupported-features/node-builtins
    this.jwks = createRemoteJWKSet(new URL(props.jwksUri));
  }

  /**
   * Performs a JWT verification and returns the parsed payload. This method is
   * intended to be used on the client-side to verify the ID token. A null value
   * will be returned if verification failed.
   *
   * @param props the JWT and verification parameters
   */
  async verifyIdToken(
    props: VerifyIdTokenProps
  ): Promise<DecodedIdToken | null> {
    try {
      const payload = jwtVerify(props.idToken, this.jwks, {
        issuer: props.issuer,
        audience: props.clientId,
      }) as unknown as DecodedRawIdToken;
      return rawToDecodedIdToken(payload);
    } catch (err) {
      return null;
    }
  }

  /**
   * Performs a JWT verification and returns the parsed payload. This method is
   * intended to be used on the server-side to verify the access token. A null
   * value will be returned if verification failed.
   *
   * @param props the JWT and verification parameters
   */
  async verifyAccessToken(
    props: VerifyAccessTokenProps
  ): Promise<DecodedAccessToken | null> {
    try {
      const payload = jwtVerify(props.accessToken, this.jwks, {
        issuer: props.issuer,
        audience: props.audience,
      }) as unknown as DecodedRawAccessToken;
      return rawToDecodedAccessToken(payload);
    } catch (err) {
      return null;
    }
  }
}
