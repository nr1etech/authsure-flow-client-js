import axios, {AxiosInstance} from 'axios';
import {FlowClient} from './flow-client';
import {
  exchangeClientCredentials,
  ExchangeClientCredentialsResult,
} from './oidc-functions';
import {decodeAccessToken, isExpired} from './jwt-helper';

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
  readonly clientId: string;
  /**
   * The client secret to use.
   */
  readonly clientSecret: string;
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
   * The scopes to use.
   */
  readonly scopes: string[];
  /**
   * Callback for the token exchange.
   */
  readonly callback?: ExchangeTokenCallback | ExchangeTokenCallback[];
}

/**
 * Client for the Client Credentials flow.
 */
export class ClientCredentialsFlowClient extends FlowClient {
  protected clientSecret: string;
  protected result?: ExchangeClientCredentialsResult;
  protected expiration?: number;
  protected refreshBufferSeconds: number;
  protected disableBackgroundRefresh: boolean;
  protected expirationBufferSeconds: number;
  protected intervalId?: NodeJS.Timeout;
  protected client: AxiosInstance;
  protected callbacks: ExchangeTokenCallback[];

  constructor(protected config: ClientCredentialsFlowClientConfig) {
    super(config);
    this.clientSecret = config.clientSecret;
    this.refreshBufferSeconds = config.refreshBufferSeconds ?? 60;
    this.expirationBufferSeconds = config.expirationBufferSeconds ?? 45;
    this.disableBackgroundRefresh = config.disableBackgroundRefresh ?? false;
    this.callbacks = config.callback
      ? Array.isArray(config.callback)
        ? config.callback
        : [config.callback]
      : [];
    this.client = config.client ?? axios.create();
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
      clientId: this.config.clientId,
      clientSecret: this.clientSecret,
      scope: this.config.scopes,
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
   * Gets the access token. If the access token is expired, it will be refreshed.
   */
  async getToken(): Promise<ExchangeClientCredentialsResult> {
    if (
      !this.result &&
      this.expiration !== undefined &&
      !isExpired(this.expiration, this.expirationBufferSeconds)
    ) {
      await this.exchange();
    }
    return this.result!;
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
          this.intervalId = setInterval(
            async () => {
              this.intervalId = undefined;
              await this.exchange();
            },
            (this.expiration - this.refreshBufferSeconds) * 1000
          );
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
