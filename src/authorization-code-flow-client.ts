import {
  AuthorizationCodeFlowUrl,
  AuthorizationCodeFlowUrlPkce,
  exchangeAuthorizationCode,
  exchangeAuthorizationCodePkce,
  ExchangeAuthorizationCodeResult,
  ExchangeRefreshTokenResult,
  getAuthorizationCodeFlowPkceUrl,
  getAuthorizationCodeFlowUrl,
} from './oidc-functions';
import {RefreshTokenManager} from './refresh-token-manager';
import {AxiosInstance} from 'axios';
import {FlowClient} from './flow-client';
import {AuthSureFlowClientError} from './errors';
import {JWTPayload} from 'jose';
import {decodeAccessToken, JwtVerifier} from './jwt-helper';

/**
 * Base configuration options for AuthorizationCodeFlow.
 */
export interface BaseAuthorizationCodeFlowConfig {
  /**
   * The domain to use for making requests.
   */
  readonly authSureDomain: string;
  /**
   * The client to use for making requests. If not specified, a new client will be created.
   */
  readonly client?: AxiosInstance;
  /**
   * The client ID to use.
   */
  readonly clientId: string;
  /**
   * The state to use. If not specified, a random state will be generated.
   */
  readonly state?: string;
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
  /**
   * The number of seconds before the access token expires to refresh the access token. Default is 60 seconds.
   *
   * @default 60
   */
  readonly refreshBufferSeconds?: number;
  /**
   * Disable the background refresh of the access token. Default is false.
   *
   * @default false
   */
  readonly disableBackgroundRefresh?: boolean;
  /**
   * The scopes to use.
   */
  readonly scopes?: string[];
  /**
   * The jwt verifier to use or the properties to create a new jwt verifier.
   */
  readonly jwtVerifier?: JwtVerifier;
}

/**
 * Configuration options enable AuthorizationCodeFlow.
 */
export interface AuthorizationCodeFlowConfig
  extends BaseAuthorizationCodeFlowConfig {
  /**
   * The client secret to use.
   */
  readonly clientSecret: string;
}

/**
 * Returns true if the config is for an authorization code flow.
 *
 * @param config the config to check
 */
export function isAuthorizationCodeFlowConfig(
  config: AuthorizationCodeFlowConfig | AuthorizationCodeFlowPkceConfig
): config is AuthorizationCodeFlowPkceConfig {
  return (config as AuthorizationCodeFlowConfig).clientSecret !== undefined;
}

/**
 * Configuration options enable AuthorizationCodeFlow with PKCE.
 */
export type AuthorizationCodeFlowPkceConfig = BaseAuthorizationCodeFlowConfig;

/**
 * Returns true if the config is for an authorization code flow with PKCE.
 *
 * @param config the config to check
 */
export function isAuthorizationCodeFlowPkceConfig(
  config: AuthorizationCodeFlowConfig | AuthorizationCodeFlowPkceConfig
): config is AuthorizationCodeFlowPkceConfig {
  return (config as AuthorizationCodeFlowConfig).clientSecret === undefined;
}

/**
 * Client for the Authorization Code flow.
 */
export class AuthorizationCodeFlowClient extends FlowClient {
  protected state?: string;
  protected nonce?: string;
  protected scopes?: string[];
  protected codeVerifier?: string;
  protected result?:
    | ExchangeAuthorizationCodeResult
    | ExchangeRefreshTokenResult;
  protected idToken?: string;
  protected payload?: JWTPayload;
  protected refreshTokenManager?: RefreshTokenManager;
  protected jwtVerifier: JwtVerifier;

  constructor(
    protected config:
      | AuthorizationCodeFlowConfig
      | AuthorizationCodeFlowPkceConfig
  ) {
    super(config);
    this.scopes = config.scopes;
    this.jwtVerifier = config.jwtVerifier ?? new JwtVerifier(this.jwksUri);
  }

  getAuthorizationUrl(): string {
    const params = {
      authorizationEndpoint: this.authorizationEndpoint,
      state: this.config.state,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      provider: this.config.provider,
      loginHint: this.config.loginHint,
      prompt: this.config.prompt,
      flow: this.config.flow,
      scopes: this.config.scopes,
    };
    let url: AuthorizationCodeFlowUrlPkce | AuthorizationCodeFlowUrl;
    if (isAuthorizationCodeFlowPkceConfig(this.config)) {
      url = getAuthorizationCodeFlowPkceUrl(params);
      this.codeVerifier = (url as AuthorizationCodeFlowUrlPkce).codeVerifier;
    } else {
      url = getAuthorizationCodeFlowUrl(params);
    }
    this.state = url.state;
    this.nonce = url.nonce;
    this.scopes = url.scopes;
    return url.url;
  }

  // TODO Refactor to make shorter and more readable
  async exchange(
    // eslint-disable-next-line node/no-unsupported-features/node-builtins
    queryString: URLSearchParams
  ): Promise<ExchangeAuthorizationCodeResult> {
    const error = queryString.get('error');
    if (error !== null) {
      const errorDescription = queryString.get('error_description');
      throw new AuthSureFlowClientError(
        `Authorization error: ${error} ${errorDescription ?? ''}`
      );
    }
    const code = queryString.get('code');
    if (code === null) {
      throw new AuthSureFlowClientError('No authorization code returned');
    }
    const state = queryString.get('state');
    if (state === null) {
      throw new AuthSureFlowClientError('No state returned');
    }
    if (this.state !== state) {
      throw new AuthSureFlowClientError('Invalid state');
    }
    let result: ExchangeAuthorizationCodeResult;
    if (isAuthorizationCodeFlowPkceConfig(this.config)) {
      const config = this.config as AuthorizationCodeFlowPkceConfig;
      result = await exchangeAuthorizationCodePkce({
        client: this.client,
        tokenEndpoint: this.tokenEndpoint,
        clientId: config.clientId,
        codeVerifier: this.codeVerifier!,
        code,
        scope: this.scopes!,
      });
    } else {
      const config = this.config as AuthorizationCodeFlowConfig;
      result = await exchangeAuthorizationCode({
        client: this.client,
        tokenEndpoint: this.tokenEndpoint,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        code,
        scope: this.scopes!,
      });
    }
    if (!result.idToken) {
      throw new AuthSureFlowClientError('No ID token returned');
    }
    if (!result.accessToken) {
      throw new AuthSureFlowClientError('No access token returned');
    }
    if (result.tokenType !== 'Bearer') {
      throw new AuthSureFlowClientError(
        `Unexpected token type ${result.tokenType}`
      );
    }
    if (!result.expiresIn) {
      throw new AuthSureFlowClientError('No expiration returned');
    }
    if (result.expiresIn <= 0) {
      throw new AuthSureFlowClientError('Invalid expiration returned');
    }
    if (!result.scopes) {
      throw new AuthSureFlowClientError('No scopes returned');
    }
    for (const s of this.scopes!) {
      if (!result.scopes.includes(s)) {
        throw new AuthSureFlowClientError(`Missing scope ${s} in response`);
      }
    }
    const payload = await this.jwtVerifier.verifyIdToken({
      idToken: result.idToken,
      clientId: this.config.clientId,
      issuer: this.issuer,
    });
    if (payload === null) {
      throw new AuthSureFlowClientError('Invalid ID token');
    }
    if (payload.nonce !== this.nonce) {
      throw new AuthSureFlowClientError('Invalid nonce');
    }
    const decodedAccessToken = decodeAccessToken(result.accessToken);
    if (decodedAccessToken === null) {
      throw new AuthSureFlowClientError('Invalid access token');
    }
    this.payload = payload;
    this.result = result;
    this.idToken = result.idToken;
    if (result.refreshToken) {
      this.refreshTokenManager = new RefreshTokenManager({
        clientId: this.config.clientId,
        refreshToken: result.refreshToken,
        expiration: decodedAccessToken.exp * 1000,
        tokenEndpoint: this.tokenEndpoint,
        refreshBufferSeconds: this.config.refreshBufferSeconds,
        disableBackgroundRefresh: this.config.disableBackgroundRefresh,
        callback: async refreshResult => {
          this.result = {
            accessToken: refreshResult.accessToken,
            expiresIn: refreshResult.expiresIn,
            scopes: refreshResult.scopes,
            refreshToken: refreshResult.refreshToken,
          } as ExchangeRefreshTokenResult;
        },
        client: this.client,
      });
    }
    return result;
  }

  async refresh(): Promise<void> {
    if (!this.refreshTokenManager) {
      throw new AuthSureFlowClientError('No refresh token available');
    }
    await this.refreshTokenManager.refresh();
  }

  getIdTokenPayload(): JWTPayload {
    if (!this.payload) {
      throw new AuthSureFlowClientError('No ID token available');
    }
    return this.payload;
  }

  getTokens(): ExchangeAuthorizationCodeResult {
    if (!this.result) {
      throw new AuthSureFlowClientError('No tokens available');
    }
    return {
      idToken: this.idToken!,
      ...this.result,
    };
  }

  close() {
    if (this.refreshTokenManager) {
      this.refreshTokenManager.close();
    }
  }
}
