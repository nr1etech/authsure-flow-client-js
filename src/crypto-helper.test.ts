import {generateCodeVerifier, generateCodeVerifierChallenge, generateNonce} from './crypto-helper';

test('Test generateNonce', () => {
  const nonce = generateNonce();
  expect(nonce).not.toBeNull();
  expect(nonce).not.toBeUndefined();
  expect(nonce.length).toBe(32);
});

test('Test generateCodeVerifier', () => {
  const codeVerifier = generateCodeVerifier();
  expect(codeVerifier).not.toBeNull();
  expect(codeVerifier).not.toBeUndefined();
  expect(codeVerifier.length).toBe(128);
});

test('Test generateCodeVerifierChallenge', () => {
  const codeVerifier = generateCodeVerifier();
  const codeVerifierChallenge = generateCodeVerifierChallenge(codeVerifier);
  expect(codeVerifierChallenge).not.toBeNull();
  expect(codeVerifierChallenge).not.toBeUndefined();
  expect(codeVerifierChallenge.challenge.length).toBe(43);
});

test('Test generateState', () => {
  const state = generateNonce();
  expect(state).not.toBeNull();
  expect(state).not.toBeUndefined();
  expect(state.length).toBe(32);
});
