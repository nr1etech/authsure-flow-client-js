import {AxiosInstance} from 'axios';
import {
  generateNonce,
  generateState,
  generateCodeVerifier,
  generateCodeVerifierChallenge,
} from './crypto-helper.js';

/**
 * The response from the OpenId configuration endpoint.
 */
export interface OpenIdConfiguration {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userEndpoint: string;
  readonly jwksUri: string;
  readonly scopesSupported: string[];
  readonly responseTypesSupported: string[];
  readonly tokenEndpointAuthMethodsSupported: string[];
}

interface OpenIdConfigurationResponse {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
  readonly jwks_uri: string;
  readonly scopes_supported: string[];
  readonly response_types_supported: string[];
  readonly token_endpoint_auth_methods_supported: string[];
}

/**
 * Returns the OpenId configuration.
 *
 * @param client the client to use for making requests
 * @param domain the domain to request the configuration from
 */
export async function getOpenIdConfiguration(
  client: AxiosInstance,
  domain: string
): Promise<OpenIdConfiguration> {
  const response = await client.get<OpenIdConfigurationResponse>(
    `https://${domain}/.well-known/openid-configuration`
  );
  return {
    issuer: response.data.issuer,
    authorizationEndpoint: response.data.authorization_endpoint,
    tokenEndpoint: response.data.token_endpoint,
    userEndpoint: response.data.userinfo_endpoint,
    jwksUri: response.data.jwks_uri,
    scopesSupported: response.data.scopes_supported,
    responseTypesSupported: response.data.response_types_supported,
    tokenEndpointAuthMethodsSupported:
      response.data.token_endpoint_auth_methods_supported,
  };
}

/**
 * Options for generating an authorization code flow URL.
 */
export interface AuthorizationCodeFlowOptions {
  /**
   * The authorization endpoint to use.
   */
  readonly authorizationEndpoint: string;
  /**
   * The state to use. If not specified, a random state will be generated.
   */
  readonly state?: string;
  /**
   * The scope(s) to use.
   */
  readonly scope?: string | string[];
  /**
   * The nonce to use. If not specified, a random nonce will be generated.
   */
  readonly nonce?: string;
  /**
   * The client ID to use.
   */
  readonly clientId: string;
  /**
   * The redirect URI to use. If not specified the default redirect URI configured for the client or flow will be used.
   */
  readonly redirectUri?: string;
  /**
   * The provider to use. If not specified, the user will be prompted to select a provider.
   */
  readonly provider?: string;
  /**
   * The login hint to use. This is used by Google and Microsoft providers to prefill in the email address.
   */
  readonly loginHint?: string;
  /**
   * The prompt to use. This is used by Google and Microsoft providers to prevent account selection when set to 'none'.
   */
  readonly prompt?: string;
  /**
   * The flow to use. If not specified, the client configured flow or the default flow will be used.
   */
  readonly flow?: string;
}

/**
 * The generated authorization code flow URL with state, nonce and scopes used.
 */
export interface AuthorizationCodeFlowUrl {
  readonly url: string;
  readonly state: string;
  readonly nonce: string;
  readonly scopes: string[];
}

/**
 * Generates a URL to start an authorization code flow.
 *
 * @param options the options to use when generating the URL
 */
export function getAuthorizationCodeFlowUrl(
  options: AuthorizationCodeFlowOptions
): AuthorizationCodeFlowUrl {
  let scopes: string[] = [];
  if (options.scope) {
    scopes = Array.isArray(options.scope)
      ? options.scope
      : options.scope.split(' ');
  }
  // Push base scopes if they are not already included as they are required for the flow to work
  for (const s of ['openid', 'profile', 'email']) {
    if (!scopes.includes(s)) {
      scopes.push(s);
    }
  }
  // Add flow to scopes if provided
  if (options.flow) {
    for (const s of scopes) {
      if (s.startsWith('authsure:flow:')) {
        throw new Error(
          'Cannot specify authsure:flow scope when flow is specified'
        );
      }
    }
    scopes.push(`authsure:flow:${options.flow}`);
  }
  const state = options.state ?? generateState();
  const nonce = options.nonce ?? generateNonce();
  return {
    url:
      `${options.authorizationEndpoint}?` +
      'response_type=code&' +
      `client_id=${options.clientId}&` +
      `scope=${scopes.join(' ')}&` +
      `state=${state}&` +
      `nonce=${nonce}` +
      (options.redirectUri ? `&redirect_uri=${options.redirectUri}` : '') +
      (options.loginHint ? `&login_hint=${options.loginHint}` : '') +
      (options.prompt ? `&prompt=${options.prompt}` : '') +
      (options.provider ? `&provider=${options.provider}` : ''),
    state,
    nonce,
    scopes,
  };
}

/**
 * Options for generating an authorization code flow URL with PKCE.
 */
export interface AuthorizationCodeFlowPkceOptions
  extends AuthorizationCodeFlowOptions {
  readonly codeVerifier?: string;
}

/**
 * The generated authorization code flow URL with state, nonce, scopes and code verifier used.
 */
export interface AuthorizationCodeFlowUrlPkce extends AuthorizationCodeFlowUrl {
  readonly codeVerifier: string;
}

/**
 * Returns true if the options are for an authorization code flow with PKCE.
 *
 * @param url the url to check
 */
export function isAuthorizationCodeFlowPkceUrl(
  url: AuthorizationCodeFlowUrl
): url is AuthorizationCodeFlowUrlPkce {
  return (url as AuthorizationCodeFlowUrlPkce).codeVerifier !== undefined;
}

/**
 * Generates a URL to start an authorization code flow with PKCE.
 *
 * @param options the options to use when generating the URL
 */
export function getAuthorizationCodeFlowPkceUrl(
  options: AuthorizationCodeFlowPkceOptions
): AuthorizationCodeFlowUrlPkce {
  const url = getAuthorizationCodeFlowUrl(options);
  const codeVerifier = options.codeVerifier ?? generateCodeVerifier();
  const codeChallenge = generateCodeVerifierChallenge(codeVerifier);
  return {
    ...url,
    url: `${url.url}&code_challenge=${codeChallenge.challenge}&code_challenge_method=${codeChallenge.method}`,
    codeVerifier,
  };
}

interface TokenResponse {
  readonly id_token?: string;
  readonly access_token: string;
  readonly expires_in: number;
  readonly token_type: string;
  readonly scope: string;
  readonly refresh_token?: string;
}

/**
 * Properties for exchangeAuthorizationCode.
 */
export interface ExchangeAuthorizationCodeProps {
  readonly client: AxiosInstance;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly code: string;
  readonly scope: string | string[];
}

/**
 * The result from exchanging an authorization code for an access token.
 */
export interface ExchangeAuthorizationCodeResult {
  readonly idToken: string;
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly tokenType: string;
  readonly scopes: string[];
  readonly refreshToken?: string;
}

function toExchangeAuthorizationCodeResult(
  res: TokenResponse
): ExchangeAuthorizationCodeResult {
  return {
    idToken: res.id_token!,
    accessToken: res.access_token,
    expiresIn: res.expires_in,
    tokenType: res.token_type,
    scopes: res.scope.split(' '),
    refreshToken: res.refresh_token,
  };
}

/**
 * Exchanges an authorization code for an access token.
 *
 * @param props the properties to use when exchanging the authorization code
 */
export async function exchangeAuthorizationCode(
  props: ExchangeAuthorizationCodeProps
): Promise<ExchangeAuthorizationCodeResult> {
  const result = await props.client.post<TokenResponse>(
    props.tokenEndpoint,
    {
      grant_type: 'authorization_code',
      client_id: props.clientId,
      client_secret: props.clientSecret,
      code: props.code,
      scope: Array.isArray(props.scope) ? props.scope.join(' ') : props.scope,
    },
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
  return toExchangeAuthorizationCodeResult(result.data);
}

/**
 * Properties for exchangeAuthorizationCodePkce.
 */
export interface ExchangeAuthorizationCodePkceProps {
  readonly client: AxiosInstance;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly codeVerifier: string;
  readonly code: string;
  readonly scope: string | string[];
}

/**
 * Exchanges an authorization code for an access token with PKCE.
 *
 * @param props the properties to use when exchanging the authorization code
 */
export async function exchangeAuthorizationCodePkce(
  props: ExchangeAuthorizationCodePkceProps
): Promise<ExchangeAuthorizationCodeResult> {
  const result = await props.client.post<TokenResponse>(
    props.tokenEndpoint,
    {
      grant_type: 'authorization_code',
      client_id: props.clientId,
      code_verifier: props.codeVerifier,
      code: props.code,
      scope: Array.isArray(props.scope) ? props.scope.join(' ') : props.scope,
    },
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
  return toExchangeAuthorizationCodeResult(result.data);
}

/**
 * Properties for exchangeClientCredentials.
 */
export interface ExchangeClientCredentialsProps {
  readonly client: AxiosInstance;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scope: string | string[];
}

/**
 * The result from exchanging client credentials for an access token.
 */
export interface ExchangeClientCredentialsResult {
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly tokenType: string;
  readonly scopes: string[];
}

/**
 * Exchanges client credentials for an access token.
 *
 * @param props the properties to use when exchanging the client credentials
 */
export async function exchangeClientCredentials(
  props: ExchangeClientCredentialsProps
): Promise<ExchangeClientCredentialsResult> {
  const result = await props.client.post<TokenResponse>(
    props.tokenEndpoint,
    {
      grant_type: 'client_credentials',
      client_id: props.clientId,
      client_secret: props.clientSecret,
      scope: Array.isArray(props.scope) ? props.scope.join(' ') : props.scope,
    },
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
  return {
    accessToken: result.data.access_token,
    expiresIn: result.data.expires_in,
    tokenType: result.data.token_type,
    scopes: result.data.scope.split(' '),
  };
}

/**
 * Properties for exchangeRefreshToken.
 */
export interface ExchangeRefreshTokenProps {
  readonly client: AxiosInstance;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly refreshToken: string;
}

/**
 * The result from exchanging a refresh token for an access token.
 */
export interface ExchangeRefreshTokenResult {
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly tokenType: string;
  readonly scopes: string[];
  readonly refreshToken: string;
}

/**
 * Refreshes an access token using a refresh token.
 *
 * @param props the properties to use when refreshing the access token
 */
export async function exchangeRefreshToken(
  props: ExchangeRefreshTokenProps
): Promise<ExchangeRefreshTokenResult> {
  const response = await props.client.post<TokenResponse>(
    props.tokenEndpoint,
    {
      client_id: props.clientId,
      grant_type: 'refresh_token',
      refresh_token: props.refreshToken,
    },
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );
  return {
    accessToken: response.data.access_token,
    expiresIn: response.data.expires_in,
    tokenType: response.data.token_type,
    scopes: response.data.scope.split(' '),
    refreshToken: response.data.refresh_token!,
  };
}
