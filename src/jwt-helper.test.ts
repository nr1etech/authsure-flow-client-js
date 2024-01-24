import {
  decodeAccessToken,
  decodeAccessTokenSafe,
  isExpired,
  isTokenExpired,
  JwtVerifier,
} from './jwt-helper';
import {SignJWT, createLocalJWKSet, generateKeyPair, exportJWK} from 'jose';

test('Test isExpired', () => {
  const exp = (Date.now() + 1000) / 1000;
  expect(isExpired(exp)).toBe(false);
  expect(isExpired(exp, 2)).toBe(true);
});

test('Test isTokenExpired', () => {
  const exp = (Date.now() + 1000) / 1000;
  const token = {exp, nbf: 0, iat: 0};
  expect(isTokenExpired(token)).toBe(false);
  expect(isTokenExpired(token, 2)).toBe(true);
});

async function setupJwks() {
  const {publicKey, privateKey} = await generateKeyPair('RS256');
  const jwks = createLocalJWKSet({
    keys: [
      {
        kid: 'test',
        ...(await exportJWK(publicKey)),
      },
    ],
  });
  return {jwks, privateKey};
}

test('Test verifyIdToken', async () => {
  const {jwks, privateKey} = await setupJwks();
  const verifier = new JwtVerifier(jwks);
  const exp = Date.now() / 1000 + 30000;
  const iat = Date.now() / 1000;
  const nbf = Date.now() / 1000 - 1000;
  const token = await new SignJWT({
    aud: 'test',
    iss: 'test',
    sub: 'test',
    email: 'test@example.com',
    name: 'Test User',
    given_name: 'Test',
    family_name: 'User',
    idp: 'test',
    provider_id: 'test',
    provider_type: 'test',
    provider_login_hint: 'test',
    provider_data: {
      givenName: 'Test',
      familyName: 'User',
      name: 'Test User',
      externalId: '1234',
      asOfDate: Date.now(),
      email: 'test@example.com',
    },
    nonce: '1234',
    jti: '1234',
    nbf,
    iat,
    exp,
  })
    .setProtectedHeader({
      alg: 'RS256',
      kid: 'test',
      typ: 'JWT',
    })
    .sign(privateKey);
  const decoded = await verifier.verifyIdToken({
    idToken: token,
    clientId: 'test', // aud field
    issuer: 'test',
  });
  const expectedDecoded = {
    iss: 'test',
    sub: 'test',
    aud: ['test'],
    jti: '1234',
    email: 'test@example.com',
    name: 'Test User',
    givenName: 'Test',
    familyName: 'User',
    idp: 'test',
    providerId: 'test',
    providerType: 'test',
    providerLoginHint: 'test',
    providerData: {
      givenName: 'Test',
      familyName: 'User',
      name: 'Test User',
      externalId: '1234',
      asOfDate: expect.any(Number),
      email: 'test@example.com',
    },
    nonce: '1234',
    nbf,
    exp,
    iat,
  };
  expect(decoded).toEqual(expectedDecoded);
  const result = await verifier.verifyIdTokenSafe({
    idToken: token,
    clientId: 'test', // aud field
    issuer: 'test',
  });
  expect(result).toEqual({
    success: true,
    error: null,
    token: result.token,
  });
});

test('Test verifyAccessToken', async () => {
  const {jwks, privateKey} = await setupJwks();
  const verifier = new JwtVerifier(jwks);
  const exp = Date.now() / 1000 + 30000;
  const iat = Date.now() / 1000;
  const nbf = Date.now() / 1000 - 1000;
  const token = await new SignJWT({
    iss: 'test',
    sub: 'test',
    aud: 'test',
    jti: '1234',
    scope: 'test moo',
    client_id: 'test',
    idp: 'test',
    nbf,
    iat,
    exp,
  })
    .setProtectedHeader({
      alg: 'RS256',
      kid: 'test',
      typ: 'JWT',
    })
    .sign(privateKey);
  const decoded = await verifier.verifyAccessToken({
    accessToken: token,
    audience: 'test',
    issuer: 'test',
  });
  const expectedDecoded = {
    iss: 'test',
    sub: 'test',
    aud: ['test'],
    jti: '1234',
    scopes: ['test', 'moo'],
    clientId: 'test',
    idp: 'test',
    nbf,
    exp,
    iat,
  };
  expect(decoded).toEqual(expectedDecoded);
  const result = await verifier.verifyAccessTokenSafe({
    accessToken: token,
    audience: 'test',
    issuer: 'test',
  });
  expect(result).toEqual({
    success: true,
    error: null,
    token: result.token,
  });
});

test('Test decodeAccessToken', async () => {
  const {publicKey, privateKey} = await generateKeyPair('RS256');
  const exp = Date.now() / 1000 + 30000;
  const iat = Date.now() / 1000;
  const nbf = Date.now() / 1000 - 1000;
  const token = await new SignJWT({
    iss: 'test',
    sub: 'test',
    aud: 'test',
    jti: '1234',
    scope: 'test moo',
    client_id: 'test',
    idp: 'test',
    nbf,
    iat,
    exp,
  })
    .setProtectedHeader({
      alg: 'RS256',
      kid: 'test',
      typ: 'JWT',
    })
    .sign(privateKey);
  const decoded = decodeAccessToken(token);
  const expectedDecoded = {
    iss: 'test',
    sub: 'test',
    aud: ['test'],
    jti: '1234',
    scopes: ['test', 'moo'],
    clientId: 'test',
    idp: 'test',
    nbf,
    exp,
    iat,
  };
  expect(decoded).toEqual(expectedDecoded);
  const result = decodeAccessTokenSafe(token);
  expect(result).toEqual({
    success: true,
    error: null,
    token: result.token,
  });
});
