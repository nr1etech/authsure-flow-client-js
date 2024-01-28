import {ClientCredentialsFlowClient} from './client-credentials-flow-client.js';
import {JwtVerifier} from './jwt-helper.js';
import {sleep} from '@nr1e/commons/lang';
import {ExchangeClientCredentialsResult} from './oidc-functions.js';

let refreshedToken: ExchangeClientCredentialsResult | undefined = undefined;

async function callback(
  accessToken: ExchangeClientCredentialsResult
): Promise<void> {
  refreshedToken = accessToken;
}

test('Test Happy Path Client Credentials Flow', async () => {
  // These credentials are specific to integration tests in this repository. They do not grant access to anything
  // important, and they belong to an AuthSure organization that is only used for testing. They are not secrets.
  const clientId = 'flow-client-js-test';
  const clientSecret = 'paxxXuyWhiLh0taW4uWPtF_A94m9aPiAbvuLcyIy4SfUe5ecssG_pNNbPvPLTn9T';

  const client = new ClientCredentialsFlowClient({
    authSureDomain: 'test.authsure.io',
    clientId,
    clientSecret,
    scopes: ['fakeapi'],
    callback,
    expirationBufferSeconds: 0,
    refreshBufferSeconds: 0,
  });

  const result1 = await client.getTokenSafe();
  expect(result1).toBeDefined();
  expect(result1.success).toBe(true);
  expect(result1.error).toBeNull();
  expect(result1.result).toBeDefined();

  const result2 = await client.getTokenSafe();
  expect(result2.result).toEqual(result1.result);

  const result3 = await client.exchangeSafe();
  expect(result3.result?.accessToken).toBeDefined();
  expect(result3.result).not.toEqual(result1.result);

  const verifier = new JwtVerifier('test.authsure.io');
  const verifyResult = await verifier.verifyAccessTokenSafe({
    accessToken: result3.result!.accessToken,
    audience: 'fakeapi',
    issuer: 'https://test.authsure.io',
  });
  expect(verifyResult.success).toBe(true);
  expect(verifyResult.error).toBeNull();
  expect(verifyResult.result).toBeDefined();
  console.log(verifyResult);
  expect(verifyResult.result?.iss).toEqual('https://test.authsure.io');
  expect(verifyResult.result?.aud).toEqual(['fakeapi']);
  expect(verifyResult.result?.sub).toBeUndefined();
  expect(verifyResult.result?.scopes).toEqual(['fakeapi']);
  expect(verifyResult.result?.clientId).toEqual(clientId);
  expect(verifyResult.result?.idp).toBeUndefined();
  refreshedToken = undefined;
  await sleep(11000);
  expect(refreshedToken).toBeDefined();
  expect(refreshedToken!.accessToken).not.toEqual(result3.result?.accessToken);
  const result4 = await client.getTokenSafe();
  expect(refreshedToken!.accessToken).toEqual(result4.result?.accessToken);

  client.close();
});
