import axios, {AxiosInstance} from 'axios';
import {
  exchangeRefreshToken,
  ExchangeRefreshTokenResult,
} from './oidc-functions';
import {AuthSureFlowClientError} from './errors';
import {decodeAccessToken} from './jwt-helper';

/**
 * Callback for the refresh token.
 */
export type RefreshTokenCallback = (
  refreshToken: ExchangeRefreshTokenResult
) => Promise<void>;

/**
 * Options for the RefreshTokenManager.
 */
export interface RefreshTokenManagerProps {
  /**
   * The client ID.
   */
  readonly clientId: string;
  /**
   * The refresh token.
   */
  readonly refreshToken: string;
  /**
   * The date the access token expires.
   */
  readonly expiration: number;
  /**
   * The token endpoint.
   */
  readonly tokenEndpoint: string;
  /**
   * The number of seconds before the access token expires to refresh the access token. Default is 60 seconds.
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
   * @default false
   */
  readonly disableBackgroundRefresh?: boolean;
  /**
   * Callback for the refresh token.
   */
  readonly callback?: RefreshTokenCallback | RefreshTokenCallback[];
  /**
   * The client to use for making requests. If not specified, a new client will be created.
   */
  readonly client?: AxiosInstance;
}

/**
 * Manages refreshing an access token using a refresh token.
 */
export class RefreshTokenManager {
  protected clientId: string;
  protected refreshToken: string;
  protected tokenEndpoint: string;
  protected refreshBufferSeconds: number;
  protected disableBackgroundRefresh: boolean;
  protected expirationBufferSeconds: number;
  protected client: AxiosInstance;
  protected expiration: number;
  protected intervalId?: NodeJS.Timeout;
  protected callbacks: RefreshTokenCallback[];

  constructor(props: RefreshTokenManagerProps) {
    this.clientId = props.clientId;
    this.refreshToken = props.refreshToken;
    this.expiration = props.expiration;
    this.tokenEndpoint = props.tokenEndpoint;
    this.refreshBufferSeconds = props.refreshBufferSeconds ?? 60;
    this.expirationBufferSeconds = props.expirationBufferSeconds ?? 45;
    this.disableBackgroundRefresh = props.disableBackgroundRefresh ?? false;
    this.callbacks = props.callback
      ? Array.isArray(props.callback)
        ? props.callback
        : [props.callback]
      : [];
    this.client = props.client ?? axios.create();
    if (!this.disableBackgroundRefresh) {
      this.start();
    }
  }

  /**
   * Adds a callback for the refresh token.
   *
   * @param callback the callback to add
   */
  callback(callback: RefreshTokenCallback): void {
    this.callbacks.push(callback);
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
   * Starts the background refresh of the access and refresh token. This is called automatically unless disableBackgroundRefresh is set to true.
   */
  start(): void {
    if (this.intervalId) {
      return;
    } else {
      if (!this.disableBackgroundRefresh) {
        this.intervalId = setInterval(
          async () => {
            this.intervalId = undefined;
            await this.refresh();
          },
          (this.expiration - this.refreshBufferSeconds) * 1000
        );
      }
    }
  }

  protected async executeCallback(
    callback: RefreshTokenCallback,
    response: ExchangeRefreshTokenResult
  ): Promise<void> {
    try {
      await callback(response);
    } catch (err) {
      console.log('Error executing callback', err);
    }
  }

  protected async executeCallbacks(
    response: ExchangeRefreshTokenResult
  ): Promise<void> {
    const promises = this.callbacks.map(callback =>
      this.executeCallback(callback, response)
    );
    await Promise.all(promises);
  }

  /**
   * Refreshes the access and refresh token. This is called automatically unless disableBackgroundRefresh is set to true.
   * Be aware this function doesn't schedule the next refresh until all callbacks return.
   */
  async refresh(): Promise<ExchangeRefreshTokenResult> {
    this.stop();
    const token = await exchangeRefreshToken({
      client: this.client,
      tokenEndpoint: this.tokenEndpoint,
      clientId: this.clientId,
      refreshToken: this.refreshToken,
    });
    if (!token.refreshToken) {
      throw new AuthSureFlowClientError('Refresh token not returned');
    }
    this.refreshToken = token.refreshToken;
    const decoded = decodeAccessToken(token.accessToken);
    if (decoded === null) {
      throw new AuthSureFlowClientError('Invalid access token');
    }
    this.expiration = (decoded.exp - this.expirationBufferSeconds) * 1000;
    await this.executeCallbacks(token);
    this.start();
    return token;
  }

  /**
   * Retrieves the current refresh token and expiration.
   */
  getRefreshToken(): string {
    return this.refreshToken;
  }

  /**
   * Closes the manager instance by stopping the background refresh and clearing the refresh token.
   */
  close() {
    this.stop();
    this.refreshToken = '';
  }
}
