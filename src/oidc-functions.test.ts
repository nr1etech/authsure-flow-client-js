// eslint-disable-next-line n/no-unpublished-import
import {expect, test} from 'vitest';
import axios from 'axios';
import {
  getAuthorizationCodeFlowPkceUrl,
  getAuthorizationCodeFlowUrl,
  getOpenIdConfiguration,
  isAuthorizationCodeFlowPkceUrl,
} from './oidc-functions.js';

test('Test getOpenIdConfiguration', async () => {
  const client = axios.create();
  const config = await getOpenIdConfiguration(client, 'secure.authsure.io');
  expect(config.issuer).toBe('https://secure.authsure.io');
});

test('Test getAuthorizationCodeFlowUrl', () => {
  let url = getAuthorizationCodeFlowUrl({
    authorizationEndpoint: 'https://secure.authsure.io/connect/authorize',
    state: 'test',
    scope: 'openid profile email test',
    nonce: '1234',
    clientId: 'test',
    redirectUri: 'https://test.example.com',
    provider: 'Google',
    loginHint: 'test@example.com',
    prompt: 'none',
    flow: 'test',
  });
  expect(url.url).toBeDefined();
  expect(url.state).toEqual('test');
  expect(url.nonce).toEqual('1234');
  expect(url.scopes).toEqual([
    'openid',
    'profile',
    'email',
    'test',
    'authsure:flow:test',
  ]);
  url = getAuthorizationCodeFlowUrl({
    authorizationEndpoint: 'https://secure.authsure.io/connect/authorize',
    scope: 'openid profile email test',
    clientId: 'test',
    redirectUri: 'https://test.example.com',
    provider: 'Google',
    loginHint: 'test@example.com',
    prompt: 'none',
    flow: 'test',
  });
  expect(url.state).toBeDefined();
  expect(url.nonce).toBeDefined();
  expect(isAuthorizationCodeFlowPkceUrl(url)).toBe(false);
});

test('Test getAuthorizationCodeFlowPkceUrl', () => {
  const url = getAuthorizationCodeFlowPkceUrl({
    authorizationEndpoint: 'https://secure.authsure.io/connect/authorize',
    state: 'test',
    scope: 'openid profile email test',
    nonce: '1234',
    clientId: 'test',
    redirectUri: 'https://test.example.com',
    provider: 'Google',
    loginHint: 'test@example.com',
    prompt: 'none',
    flow: 'test',
    codeVerifier: 'test',
  });
  expect(url.url).toBeDefined();
  expect(url.state).toEqual('test');
  expect(url.nonce).toEqual('1234');
  expect(url.scopes).toEqual([
    'openid',
    'profile',
    'email',
    'test',
    'authsure:flow:test',
  ]);
  expect(url.codeVerifier).toEqual('test');
  expect(url.url).toContain('code_challenge=');
  expect(url.url).toContain('code_challenge_method=');
});

test('Test exchangeAuthorizationCode', async () => {
  // TODO Need to implement this
  expect(true).toBe(true);
});

test('Test exchangeAuthorizationCodePkce', async () => {
  // TODO Need to implement this
  expect(true).toBe(true);
});

test('Test exchangeClientCredentials', async () => {
  // TODO Need to implement this
  expect(true).toBe(true);
});

test('Test exchangeRefreshToken', async () => {
  // TODO Need to implement this
  expect(true).toBe(true);
});
