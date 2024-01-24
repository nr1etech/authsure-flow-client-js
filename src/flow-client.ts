import axios, {AxiosInstance} from 'axios';
import {getOpenIdConfiguration, OpenIdConfiguration} from './oidc-functions';

/**
 * Configuration for the Flow client.
 */
export interface FlowClientConfig {
  readonly authSureDomain: string;
  readonly client?: AxiosInstance;
}

/**
 * Base class for all Flow clients.
 */
export abstract class FlowClient {
  protected readonly authSureDomain: string;
  protected readonly client: AxiosInstance;
  protected readonly jwksUri: string;
  protected readonly authorizationEndpoint: string;
  protected readonly tokenEndpoint: string;
  protected readonly issuer: string;
  protected openIdConfiguration?: OpenIdConfiguration;
  constructor(config: FlowClientConfig) {
    this.authSureDomain = config.authSureDomain;
    // Coded this way to avoid an extra HTTP request to get the OpenId configuration
    this.jwksUri = `https://${this.authSureDomain}/.well-known/openid-configuration/jwks`;
    this.authorizationEndpoint = `https://${this.authSureDomain}/connect/authorize`;
    this.tokenEndpoint = `https://${this.authSureDomain}/connect/token`;
    this.issuer = `https://${this.authSureDomain}`;
    this.client = config.client ?? axios.create();
  }

  /**
   * Returns the OpenId configuration.
   */
  async getConfiguration(): Promise<OpenIdConfiguration> {
    if (!this.openIdConfiguration) {
      this.openIdConfiguration = await getOpenIdConfiguration(
        this.client,
        this.authSureDomain
      );
    }
    return this.openIdConfiguration;
  }
}
