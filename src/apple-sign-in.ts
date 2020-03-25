import { URL } from "url";
import jwt from "jsonwebtoken";
import fs from "fs";
import NodeRSA from "node-rsa";
import axios from 'axios';

const ENDPOINT_URL = "https://appleid.apple.com";
// FIXME: Implement this change: https://github.com/Techofficer/node-apple-signin/pull/3 
// const DEFAULT_SCOPE = "email";
const TOKEN_ISSUER = "https://appleid.apple.com";

export function getAuthorizationUrl(options: {
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
}): string {
  if (!options.clientId) throw Error("clientId is empty");
  if (!options.redirectUri) throw Error("redirectUri is empty");

  const url = new URL(ENDPOINT_URL);
  url.pathname = "/auth/authorize";

  url.searchParams.append("response_type", "code");
  // TODO: should it really fallback to "state" string?
  url.searchParams.append("state", options.state || "state");
  url.searchParams.append("client_id", options.clientId);
  url.searchParams.append("redirect_uri", options.redirectUri);

  if (options.scope) {
    url.searchParams.append("scope", "openid " + options.scope);
  } else {
    url.searchParams.append("scope", "openid");
  }

  return url.toString();
}

/**
 * As per apple docs the max duration a client secret claim can last 
 * @link https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048
 */
const MAX_CLAIM_DURATION_SECONDS = 15777000;

export interface ClientSecretOptionsBase {
  /**
   * Identifier of Apple Service ID.
   * @example "com.gotechmakers.auth.client"
   */
  clientId: string;
  teamId: string;
  keyIdentifier: string;
  /**
   * The expiration duration for registered claim key in seconds.
   * The value of which must not be greater than 15777000 (6 months in seconds) from the Current Unix Time on the
   * server.
   * @link https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048
   * @default 15777000
   */
  expirationDuration?: number;
}
export type ClientSecretOptionsWithPath = ClientSecretOptionsBase & {
  /**
  * Path to private key file
  */
  privateKeyPath: string;
};
export type ClientSecretOptions = ClientSecretOptionsBase & {
  privateKey: string;
};

/**
 * Factory function that helps to create the client secret instead of passing the private key directly but from a file path
 * @param options 
 */
export function createClientSecretFromPath (options: ClientSecretOptionsWithPath) {
  if (!options.privateKeyPath) {
    throw new Error('Missing privateKeyPath options');
  }

  if (!fs.existsSync(options.privateKeyPath)) {
    throw new Error("Can't find private key for given path");
  }

  const privateKey = fs.readFileSync(options.privateKeyPath, 'utf-8');

  if (!privateKey) {
    throw new Error('Empty key found at given privateKeyPath');
  }

  return createClientSecret({
    clientId: options.clientId,
    teamId: options.teamId,
    keyIdentifier: options.keyIdentifier,
    expirationDuration: options.expirationDuration,
    privateKey: privateKey
  })
}

export function createClientSecret(options: ClientSecretOptions): string {
  if (!options.clientId) throw new Error("clientId is empty");
  if (!options.teamId) throw new Error("teamId is empty");
  if (!options.keyIdentifier) throw new Error("keyIdentifier is empty");
  if (!options.privateKey) throw new Error('privateKey is empty');

  options.expirationDuration

  const claimDurationSeconds = options.expirationDuration || MAX_CLAIM_DURATION_SECONDS;
  if (claimDurationSeconds > MAX_CLAIM_DURATION_SECONDS) {
    throw new Error('Claim duration can\t exceed 6 months');
  }

  const timeNowSeconds = Math.floor(Date.now() / 1000);

  const claims = {
    iss: options.teamId,
    iat: timeNowSeconds,
    exp: timeNowSeconds + claimDurationSeconds,
    aud: ENDPOINT_URL,
    sub: options.clientId
  };
  const header = { alg: "ES256", kid: options.keyIdentifier };
  return jwt.sign(claims, options.privateKey, { algorithm: "ES256", header });
}

/**
 * The response token object returned on a successful request.
 * @link https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
 */
export interface TokenResponse {
  // (Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
  access_token: string;
  // The amount of time, in seconds, before the access token expires.
  expires_in: number;
  // A JSON Web Token that contains the user’s identity information.
  id_token: string;
  // The refresh token used to regenerate new access tokens. Store this token securely on your server.
  refresh_token: string;
  // The type of access token. It will always be bearer.
  token_type: string;
}

export async function getAuthorizationToken(
  code: string,
  options: {
    clientId: string;
    clientSecret: string;
    redirectUri?: string;
  }
): Promise<TokenResponse> {
  if (!options.clientId) throw new Error("clientId is empty");
  if (!options.clientSecret) throw new Error("clientSecret is empty");

  const url = new URL(ENDPOINT_URL);
  url.pathname = "/auth/token";

  const data = {
    client_id: options.clientId,
    client_secret: options.clientSecret,
    code,
    grant_type: "authorization_code",
    redirect_uri: options.redirectUri
  };

  const response = await axios(url.toString(), { method: "post", data });
  return response.data as TokenResponse;
}

export async function refreshAuthorizationToken(
  refreshToken: string,
  options: {
    clientId: string;
    clientSecret: string;
  }
) {
  if (!options.clientId) throw new Error("clientId is empty");
  if (!options.clientSecret) throw new Error("clientSecret is empty");

  const url = new URL(ENDPOINT_URL);
  url.pathname = "/auth/token";

  const data = {
    client_id: options.clientId,
    client_secret: options.clientSecret,
    refresh_token: refreshToken,
    grant_type: "refresh_token"
  };

  const response = await axios(url.toString(), { method: "post", data });
  return response.data;
}

/**
 * An object that defines a single JSON Web Key.
 * @link https://developer.apple.com/documentation/sign_in_with_apple/jwkset/keys
 */
interface JwkKey {
  // The encryption algorithm used to encrypt the token.
  alg: string;
  // The exponent value for the RSA public key.
  e: string;
  // A 10-character identifier key, obtained from your developer account.
  kid: string;
  // The key type parameter setting. This must be set to "RSA".
  kty: string;
  // The modulus value for the RSA public key.
  n: string;
  // The intended use for the public key.
  use: string;
}

// TODO: rename to getApplePublicKeys and add multi key response
export async function getApplePublicKeys(): Promise<string[]> {
  const url = new URL(ENDPOINT_URL);
  url.pathname = "/auth/keys";

  const response = await axios(url.toString());
  const keys = response.data as JwkKey[];

  const publicKeys = keys.map(key => {
    // TODO: Not sure if i need to create a new NodeRSA for each?
    const pubKey = new NodeRSA();
    // TODO: what is 'components-public'?
    pubKey.importKey({ n: Buffer.from(key.n, "base64"), e: Buffer.from(key.e, "base64") }, "components-public");
    return pubKey.exportKey("public");
  });

  return publicKeys;
}

export async function verifyIdToken(idToken: string, clientId: string) {
  const applePublicKeys = await getApplePublicKeys();
  // TODO: add multiple key support
  const applePublicKey = applePublicKeys[0];
  const jwtClaims = jwt.verify(idToken, applePublicKey, { algorithms: ["RS256"] }) as any;

  if (typeof jwtClaims === "string") {
    throw new Error("Invalid jwtClaims");
  }

  if (jwtClaims.iss !== TOKEN_ISSUER)
    throw new Error(
      "id token not issued by correct OpenID provider - expected: " + TOKEN_ISSUER + " | from: " + jwtClaims.iss
    );
  if (clientId !== undefined && jwtClaims.aud !== clientId)
    throw new Error("aud parameter does not include this client - is: " + jwtClaims.aud + "| expected: " + clientId);
  if (jwtClaims.exp < Date.now() / 1000) throw new Error("id token has expired");

  return jwtClaims;
}
