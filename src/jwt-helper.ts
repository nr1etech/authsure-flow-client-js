import {
  createRemoteJWKSet,
  FlattenedJWSInput,
  JWSHeaderParameters,
  JWTPayload,
  jwtVerify,
  KeyLike,
  decodeJwt,
  JWTVerifyResult,
} from 'jose';
import {AuthSureFlowClientError, isAuthSureFlowClientError} from './errors.js';
import {SafeResult} from './safe-result.js';

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
 * @param exp the expiration timestamp in seconds
 * @param bufferSeconds the number of seconds before the expiration timestamp to consider the token expired
 */
export function isExpired(exp: number, bufferSeconds?: number) {
  return Date.now() > (exp - (bufferSeconds ?? 0)) * 1000;
}

/**
 * Checks if a token is expired.
 *
 * @param token the token to check
 * @param bufferSeconds the number of seconds before the expiration timestamp to consider the token expired
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
    throw new AuthSureFlowClientError('Missing name in ID token');
  }
  if (payload.aud === undefined || payload.aud === null) {
    throw new AuthSureFlowClientError('Missing aud in ID token');
  }
  if (payload.iss === undefined || payload.iss === null) {
    throw new AuthSureFlowClientError('Missing iss in ID token');
  }
  if (payload.sub === undefined || payload.sub === null) {
    throw new AuthSureFlowClientError('Missing sub in ID token');
  }
  if (payload.jti === undefined || payload.jti === null) {
    throw new AuthSureFlowClientError('Missing jti in ID token');
  }
  if (payload.nbf === undefined || payload.nbf === null) {
    throw new AuthSureFlowClientError('Missing nbf in ID token');
  }
  if (payload.exp === undefined || payload.exp === null) {
    throw new AuthSureFlowClientError('Missing exp in ID token');
  }
  if (payload.iat === undefined || payload.iat === null) {
    throw new AuthSureFlowClientError('Missing iat in ID token');
  }
  const {
    iss,
    sub,
    aud,
    jti,
    nbf,
    exp,
    iat,
    email,
    name,
    given_name,
    family_name,
    idp,
    provider_id,
    provider_type,
    provider_login_hint,
    provider_data,
    nonce,
    ...rest
  } = payload;
  return {
    iss,
    sub,
    aud: Array.isArray(aud) ? aud : [aud],
    jti,
    nbf,
    exp,
    iat,
    email,
    name,
    givenName: given_name,
    familyName: family_name,
    idp: idp,
    providerId: provider_id,
    providerType: provider_type,
    providerLoginHint: provider_login_hint,
    providerData: provider_data,
    nonce: nonce,
    ...rest,
  };
}

interface DecodedRawAccessToken extends JWTPayload {
  scope?: string;
  client_id?: string;
}

/**
 * Decoded access token.
 */
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
   * Identify provider used.
   */
  idp?: string;
  /**
   * Any other JWT Claim Set member.
   */
  [propName: string]: unknown;
}

function rawToDecodedAccessToken(
  payload: DecodedRawAccessToken
): DecodedAccessToken | null {
  if (payload.client_id === undefined || payload.client_id === null) {
    throw new AuthSureFlowClientError('Missing client_id in access token');
  }
  if (payload.aud === undefined || payload.aud === null) {
    throw new AuthSureFlowClientError('Missing aud in access token');
  }
  if (payload.iss === undefined || payload.iss === null) {
    throw new AuthSureFlowClientError('Missing iss in access token');
  }
  if (payload.jti === undefined || payload.jti === null) {
    throw new AuthSureFlowClientError('Missing jti in access token');
  }
  if (payload.nbf === undefined || payload.nbf === null) {
    throw new AuthSureFlowClientError('Missing nbf in access token');
  }
  if (payload.exp === undefined || payload.exp === null) {
    throw new AuthSureFlowClientError('Missing exp in access token');
  }
  if (payload.iat === undefined || payload.iat === null) {
    throw new AuthSureFlowClientError('Missing iat in access token');
  }
  const {iss, sub, aud, jti, nbf, exp, iat, scope, client_id, idp, ...rest} =
    payload;
  return {
    iss,
    sub,
    aud: Array.isArray(aud) ? aud : [aud],
    jti,
    nbf,
    exp,
    iat,
    scopes: scope?.split(' ') ?? [],
    clientId: client_id,
    idp: idp as string | undefined,
    ...rest,
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
  let result;
  try {
    result = decodeJwt(accessToken) as unknown as DecodedRawAccessToken;
  } catch (err) {
    if (err instanceof Error) {
      throw new AuthSureFlowClientError(
        `Failed to decode access token: ${err.message}`,
        err
      );
    }
    throw new AuthSureFlowClientError('Failed to decode access token', err);
  }
  return rawToDecodedAccessToken(result);
}

/**
 * Safe version of decodeAccessToken that returns a result object instead of throwing an error.
 *
 * @param accessToken the access token to decode
 */
export function decodeAccessTokenSafe(
  accessToken: string
): SafeResult<DecodedAccessToken> {
  try {
    return {
      success: true,
      error: null,
      result: decodeAccessToken(accessToken),
    };
  } catch (err) {
    if (isAuthSureFlowClientError(err)) {
      return {
        success: false,
        error: err,
        result: null,
      };
    }
    return {
      success: false,
      error: new AuthSureFlowClientError('Failed to decode access token', err),
      result: null,
    };
  }
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
  protected readonly jwks: Jwks;

  /**
   * Creates a new JWT verifier.
   *
   * @param jwks the JWKS instance, URL to the JWKS endpoint, or your AuthSure domain.
   */
  constructor(jwks: string | Jwks) {
    if (typeof jwks === 'string') {
      if (jwks.startsWith('https://')) {
        // eslint-disable-next-line node/no-unsupported-features/node-builtins
        this.jwks = createRemoteJWKSet(new URL(jwks));
      } else {
        this.jwks = createRemoteJWKSet(
          // eslint-disable-next-line node/no-unsupported-features/node-builtins
          new URL(`https://${jwks}/.well-known/openid-configuration/jwks`)
        );
      }
    } else {
      this.jwks = jwks;
    }
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
    let result: JWTVerifyResult<DecodedRawIdToken>;
    try {
      result = await jwtVerify(props.idToken, this.jwks, {
        issuer: props.issuer,
        audience: props.clientId,
      });
    } catch (err) {
      if (err instanceof Error) {
        throw new AuthSureFlowClientError(
          `Failed to verify ID token: ${err.message}`,
          err
        );
      }
      throw new AuthSureFlowClientError('Failed to verify ID token', err);
    }
    return rawToDecodedIdToken(result.payload);
  }

  /**
   * Safe version of verifyIdToken that returns a result object instead of throwing an error.
   *
   * @param props the JWT and verification parameters
   */
  async verifyIdTokenSafe(
    props: VerifyIdTokenProps
  ): Promise<SafeResult<DecodedIdToken>> {
    try {
      return {
        success: true,
        error: null,
        result: await this.verifyIdToken(props),
      };
    } catch (err) {
      if (isAuthSureFlowClientError(err)) {
        return {
          success: false,
          error: err,
          result: null,
        };
      }
      return {
        success: false,
        error: new AuthSureFlowClientError('Failed to verify ID token', err),
        result: null,
      };
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
    let result: JWTVerifyResult<DecodedRawAccessToken>;
    try {
      result = await jwtVerify(props.accessToken, this.jwks, {
        issuer: props.issuer,
        audience: props.audience,
      });
    } catch (err) {
      if (err instanceof Error) {
        throw new AuthSureFlowClientError(
          `Failed to verify access token: ${err.message}`,
          err
        );
      }
      throw new AuthSureFlowClientError('Failed to verify access token', err);
    }
    return rawToDecodedAccessToken(result.payload);
  }

  /**
   * Safe version of verifyAccessToken that returns a result object instead of throwing an error.
   *
   * @param props the JWT and verification parameters
   */
  async verifyAccessTokenSafe(
    props: VerifyAccessTokenProps
  ): Promise<SafeResult<DecodedAccessToken>> {
    try {
      return {
        success: true,
        error: null,
        result: await this.verifyAccessToken(props),
      };
    } catch (err) {
      if (isAuthSureFlowClientError(err)) {
        return {
          success: false,
          error: err,
          result: null,
        };
      }
      return {
        success: false,
        error: new AuthSureFlowClientError(
          'Failed to verify access token',
          err
        ),
        result: null,
      };
    }
  }
}
