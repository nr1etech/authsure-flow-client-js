import {AxiosInstance} from 'axios';
import {FlowClient} from './flow-client.js';
import {
  exchangeClientCredentials,
  ExchangeClientCredentialsResult,
} from './oidc-functions.js';
import {decodeAccessToken, isExpired} from './jwt-helper.js';
import {SafeResult} from './safe-result.js';
import {AuthSureFlowClientError, isAuthSureFlowClientError} from './errors.js';

export const DEFAULT_REFRESH_BUFFER_SECONDS = 60;
export const DEFAULT_EXPIRATION_BUFFER_SECONDS = 45;
export const DEFAULT_DISABLE_BACKGROUND_REFRESH = false;

/**
 * Callback for token exchange.
 */
export type ExchangeTokenCallback = (
  accessToken: ExchangeClientCredentialsResult
) => Promise<void>;

/**
 * Configuration for the ClientCredentialsFlowClient.
 */
export interface ClientCredentialsFlowClientConfig {
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
  readonly clientId: string | Promise<string>;
  /**
   * The client secret to use.
   */
  readonly clientSecret: string | Promise<string>;
  /**
   * The number of seconds before the access token expires to refresh the access token. Default is 60 seconds.
   *
   * @default 60
   */
  readonly refreshBufferSeconds?: number;
  /**
   * The number of seconds to subtract from the token expiration time when calculating if the token is expired.
   * Default is 45 seconds. Recommended to be less than the refreshBufferSeconds.
   *
   * @default 45
   */
  readonly expirationBufferSeconds?: number;
  /**
   * Disable the background refresh of the access token. Default is false.
   *
   * @default false
   */
  readonly disableBackgroundRefresh?: boolean;
  /**
   * The scopes to use. This can either be a space delimited string or an array of strings.
   */
  readonly scope: string | string[];
  /**
   * Callback for the token exchange.
   */
  readonly callback?: ExchangeTokenCallback | ExchangeTokenCallback[];
}

/**
 * Client for the Client Credentials flow.
 */
export class ClientCredentialsFlowClient extends FlowClient {
  protected clientId: string | Promise<string>;
  protected clientSecret: string | Promise<string>;
  protected scope: string | string[];
  protected result?: ExchangeClientCredentialsResult;
  protected expiration?: number;
  protected refreshBufferSeconds: number;
  protected disableBackgroundRefresh: boolean;
  protected expirationBufferSeconds: number;
  protected intervalId?: NodeJS.Timeout;
  protected callbacks: ExchangeTokenCallback[];

  constructor(config: ClientCredentialsFlowClientConfig) {
    super(config);
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.scope = config.scope;
    this.refreshBufferSeconds =
      config.refreshBufferSeconds ?? DEFAULT_REFRESH_BUFFER_SECONDS;
    this.expirationBufferSeconds =
      config.expirationBufferSeconds ?? DEFAULT_EXPIRATION_BUFFER_SECONDS;
    this.disableBackgroundRefresh =
      config.disableBackgroundRefresh ?? DEFAULT_DISABLE_BACKGROUND_REFRESH;
    this.callbacks = config.callback
      ? Array.isArray(config.callback)
        ? config.callback
        : [config.callback]
      : [];
  }

  /**
   * Adds a callback for the token exchange.
   *
   * @param callback the callback to add
   */
  callback(callback: ExchangeTokenCallback): void {
    this.callbacks.push(callback);
  }

  protected async executeCallback(
    callback: ExchangeTokenCallback,
    response: ExchangeClientCredentialsResult
  ): Promise<void> {
    try {
      await callback(response);
    } catch (err) {
      console.log('Error executing callback', err);
    }
  }

  protected async executeCallbacks(
    response: ExchangeClientCredentialsResult
  ): Promise<void> {
    const promises = this.callbacks.map(callback =>
      this.executeCallback(callback, response)
    );
    await Promise.all(promises);
  }

  /**
   * Exchanges the client credentials for an access token which is stored in the client.
   */
  async exchange(): Promise<ExchangeClientCredentialsResult> {
    this.stop();
    const result = await exchangeClientCredentials({
      client: this.client,
      tokenEndpoint: this.tokenEndpoint,
      clientId:
        typeof this.clientId === 'string' ? this.clientId : await this.clientId,
      clientSecret:
        typeof this.clientSecret === 'string'
          ? this.clientSecret
          : await this.clientSecret,
      scope: this.scope,
    });
    const decoded = decodeAccessToken(result.accessToken);
    if (decoded === null) {
      throw new Error('Invalid access token');
    }
    this.result = result;
    this.expiration = (decoded.exp - this.expirationBufferSeconds) * 1000;
    await this.executeCallbacks(result);
    await this.start();
    return result;
  }

  /**
   * Exchanges the client credentials for an access token which is stored in the client.
   * This method does not throw exceptions and instead returns a SafeResult which can be used to check if the operation was successful.
   */
  async exchangeSafe(): Promise<SafeResult<ExchangeClientCredentialsResult>> {
    try {
      const result = await this.exchange();
      return {
        success: true,
        error: null,
        result,
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
          'Failed to exchange client credentials',
          err
        ),
        result: null,
      };
    }
  }

  /**
   * Gets the access token. If the access token is expired, it will be refreshed.
   */
  async getToken(): Promise<ExchangeClientCredentialsResult> {
    if (
      this.result === undefined ||
      this.expiration === undefined ||
      isExpired(this.expiration, this.expirationBufferSeconds)
    ) {
      await this.exchange();
    }
    return this.result!;
  }

  /**
   * Gets the access token. If the access token is expired, it will be refreshed.
   * This method does not throw exceptions and instead returns a SafeResult which can be used to check if the operation was successful.
   */
  async getTokenSafe(): Promise<SafeResult<ExchangeClientCredentialsResult>> {
    try {
      const result = await this.getToken();
      return {
        success: true,
        error: null,
        result,
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
        error: new AuthSureFlowClientError('Failed to get token', err),
        result: null,
      };
    }
  }

  /**
   * Stops the background refresh of the access and refresh token.
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }
  }

  /**
   * Starts the background refresh the token. This is called automatically unless disableBackgroundRefresh is set to true.
   */
  async start(): Promise<void> {
    if (this.intervalId) {
      return;
    } else {
      if (!this.disableBackgroundRefresh) {
        if (this.result === undefined || this.expiration === undefined) {
          await this.exchange();
        } else {
          let timeout =
            this.expiration - Date.now() - this.refreshBufferSeconds * 1000;
          if (timeout <= 0) {
            timeout = 1000;
          }
          this.intervalId = setInterval(async () => {
            await this.exchange();
          }, timeout);
        }
      }
    }
  }

  /**
   * Closes the client and stops the background refresh of the access and refresh token.
   */
  close() {
    this.stop();
    this.result = undefined;
    this.expiration = undefined;
  }
}
