import fs from "fs";
import { URL } from "url";
import querystring from "querystring";
// import crypto from "crypto";

import jwt from "jsonwebtoken";
import createJwksClient, { JwksClient, SigningKey } from "jwks-rsa";
import axios from "axios";

export interface AppleSignInOptions {
  /**
   * Apple Service ID.
   * @example "com.my-company.my-app"
   */
  clientId: string;
  /**
   * Apple Developer Team ID.
   * @example "5B645323E8"
   */
  teamId: string;
  /**
   * Identifier of the private key.
   * @example "U3B842SVGC"
   */
  keyIdentifier: string;
  /**
   * Absolute path to private key file.
   * File extension doesn't matter, we read the file contents
   * @example '/Users/arnold/my-project/credentials/AuthKey.p8'
   */
  privateKeyPath?: string;
  /**
   * Contents of private key.
   * Prefered method if injecting private key from environments.
   * @example "-----BEGIN PRIVATE KEY-----\nMIGTAgEHIHMJKJyqGSM32AgEGC..."
   */
  privateKey?: string;
}

/**
 * The response token object returned on a successful request.
 * @link https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
 */
export interface AccessTokenResponse {
  /**
   * (Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
   */
  access_token: string;
  /**
   * The amount of time, in seconds, before the access token expires.
   */
  expires_in: number;
  /**
   * A JSON Web Token that contains the user’s identity information.
   */
  id_token: string;
  /**
   * The refresh token used to regenerate new access tokens. Store this token securely on your server.
   */
  refresh_token: string;
  /**
   * The type of access token. It will always be bearer.
   */
  token_type: string;
}

export type RefreshTokenResponse = Pick<AccessTokenResponse, "access_token" | "expires_in" | "token_type">;

/**
 * https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple#3383773
 */
export interface AppleIdTokenType {
  /**
   * The issuer-registered claim key, which has the value https://appleid.apple.com.
   * @example "https://appleid.apple.com"
   */
  iss: string;
  /**
   * The unique identifier for the user.
   * @example "001999.80b18c74c3264cad895d0eae181d8f50.1909"
   */
  sub: string;
  /**
   * Your client_id in your Apple Developer account.
   * @example "com.unity.testApp"
   */
  aud: string;
  /**
   * The expiry time for the token. This value is typically set to five minutes.
   * @example 1568671600
   */
  exp: string;
  /**
   * The time the token was issued.
   * @example 1568671000
   */
  iat: string;
  /**
   * The hash of the authorization code. It’s only used when you need to validate the authorization code.
   * @example "agyAh42GdE-O72Y4HUHypg"
   */
  c_hash: string;
  /**
   * A String value used to associate a client session and an ID token. This value is used to mitigate replay attacks and is present only if passed during the authorization request.
   */
  nonce: string;
  /**
   * A Boolean value that indicates whether the transaction is on a nonce-supported platform. If you sent a nonce in the authorization request but do not see the nonce claim in the ID token, check this claim to determine how to proceed. If this claim returns true you should treat nonce as mandatory and fail the transaction; otherwise, you can proceed treating the nonce as optional.
   */
  nonce_supported: boolean;
  /**
   * [First login only] The user's email address.
   * @example xxx@privaterelay.appleid.com
   */
  email?: string;
  /**
   * [First login only] A Boolean value that indicates whether the service has verified the email. The value of this
   * claim is always true because the servers only return verified email addresses.
   * @example true
   */
  email_verified?: boolean;

  /**
   * Determine whether email is Apple private (trough relay) one or not.
   * In my testing, is_private_email property will only be present if it is true.
   * @example true
   */
  is_private_email?: boolean;

  auth_time: number;
}

export default class AppleSignIn {
  private clientId: string;
  private teamId: string;
  private keyIdentifier: string;
  private privateKey: string;

  private jwksClient: JwksClient;

  constructor(options: AppleSignInOptions) {
    if (!options?.clientId) throw new Error("clientId is empty");
    if (!options?.teamId) throw new Error("teamId is empty");
    if (!options?.keyIdentifier) throw new Error("keyIdentifier is empty");

    this.clientId = options.clientId;
    this.teamId = options.teamId;
    this.keyIdentifier = options.keyIdentifier;

    let privateKey: string | undefined;
    if (Object.prototype.hasOwnProperty.call(options, "privateKey")) {
      privateKey = options.privateKey;
    } else if (Object.prototype.hasOwnProperty.call(options, "privateKeyPath")) {
      if (!options?.privateKeyPath) {
        throw new Error("privateKeyPath is empty");
      }
      if (!fs.existsSync(options.privateKeyPath)) {
        throw new Error("Private key file for given path doesn't exist");
      }

      privateKey = fs.readFileSync(options.privateKeyPath, "utf-8");
    }
    if (!privateKey) {
      throw new Error("Empty private key from given input method");
    }
    this.privateKey = privateKey;

    /**
     * Create jwks instance that caches 5 kid's up to 10 minutes to reduce amount calls to apple auth keys endpoint.
     * @link https://github.com/auth0/node-jwks-rsa#caching
     */
    this.jwksClient = createJwksClient({
      jwksUri: "https://appleid.apple.com/auth/keys",
    });
  }

  /**
   * Function that generates a url that can be used to redirect the user and begin the "Sign in with Apple" flow.
   * @link https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms#3332113
   */
  public getAuthorizationUrl(options: {
    /**
     * The destination URI the code was originally sent to.
     */
    redirectUri: string;
    /**
     * The amount of user information requested from Apple.
     *
     * You can request the user’s "name" or "email". You can also choose to request both, or neither.
     * Ommiting the property or providing any empty won't request any scopes.
     *
     * @example ['email']
     * @example ['name', 'email']
     */
    scope?: "name" | "email"[];
    /**
     * A unique and non-guessable value that helps prevent CSRF attacks. Usually a UUID string.
     * @link https://auth0.com/docs/protocols/oauth2/oauth-state
     */
    state?: string;
    /**
     * A String value used to associate a client session with an ID token. This value is also used to mitigate replay attacks.
     */
    nonce?: string;
  }): string {
    if (!options.redirectUri) throw new Error("redirectUri is empty");
    if (options.scope && !Array.isArray(options.scope)) throw new Error("scope must be an array");

    const url = new URL("https://appleid.apple.com/auth/authorize");
    url.searchParams.append("client_id", this.clientId);
    url.searchParams.append("redirect_uri", options.redirectUri);
    url.searchParams.append("response_type", "code");

    if (options.scope && options.scope.length) {
      url.searchParams.append("scope", options.scope.join(" "));
      /**
       * If you requested any scopes, an additional `response_mode=form_post` parameter must be set.
       * Docs: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms#3332113
       */
      // TODO: maybe add other response_mode parameters support - "query", "fragment" and "form_post"
      url.searchParams.append("response_mode", "form_post");
    }

    if (options.state) {
      url.searchParams.append("state", options.state);
    }

    if (options.nonce) {
      url.searchParams.append("nonce", options.nonce);
    }

    return url.toString();
  }

  async getAuthorizationToken(
    /**
     * A secret generated as a JSON Web Token that uses the secret key generated by the WWDR portal.
     */
    clientSecret: string,
    /**
     * A single-use authorization code that is valid for five minutes from generation.
     */
    code: string,
    options: {
      /**
       * The destination URI the code was originally sent to.
       */
      redirectUri?: string;
    }
  ): Promise<AccessTokenResponse> {
    if (!clientSecret) throw new Error("clientSecret is empty");
    if (!code) throw new Error("code is empty");

    let results;
    try {
      const response = await axios("https://appleid.apple.com/auth/token", {
        method: "post",
        data: querystring.stringify({
          /* eslint-disable @typescript-eslint/camelcase */
          client_id: this.clientId,
          client_secret: clientSecret,
          grant_type: "authorization_code",
          code,
          redirect_uri: options?.redirectUri,
          /* eslint-enable @typescript-eslint/camelcase */
        }),
      });
      results = response.data as AccessTokenResponse;
    } catch (err) {
      const statusCode = err?.response?.status;
      const reason = err?.response?.data?.error;
      if (reason) {
        throw new Error(`Authorization request failed with reason "${reason}" and status code "${statusCode}"`);
      } else {
        throw new Error(`Authorization request failed with unknown reason and status code "${statusCode}"`);
      }
    }

    return results;
  }

  async refreshAuthorizationToken(
    /**
     * A secret generated as a JSON Web Token that uses the secret key generated by the WWDR portal.
     */
    clientSecret: string,
    /**
     * The refresh token received during the authorization request.
     */
    refreshToken: string
  ): Promise<RefreshTokenResponse> {
    if (!clientSecret) throw new Error("clientSecret is empty");
    if (!refreshToken) throw new Error("refreshToken is empty");

    let results;
    try {
      const response = await axios("https://appleid.apple.com/auth/token", {
        method: "post",
        data: querystring.stringify({
          /* eslint-disable @typescript-eslint/camelcase */
          client_id: this.clientId,
          client_secret: clientSecret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          /* eslint-enable @typescript-eslint/camelcase */
        }),
      });
      results = response.data as RefreshTokenResponse;
    } catch (err) {
      const statusCode = err?.response?.status;
      const reason = err?.response?.data?.error;
      if (reason) {
        throw new Error(`Authorization request failed with reason "${reason}" and status code "${statusCode}"`);
      } else {
        throw new Error(`Authorization request failed with unknown reason and status code "${statusCode}"`);
      }
    }

    return results;
  }

  createClientSecret(options: {
    /**
     * The expiration duration for registered claim key in seconds.
     * The value of which must not be greater than 15777000 (6 months in seconds) from the Current Unix Time on the
     * server.
     * @link https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens#3262048
     * @default 15777000
     */
    expirationDuration?: number;
  }): string {
    /**
     * As per apple docs the max duration a client secret claim can last - 6 months in secods
     */
    const MAX_CLAIM_DURATION_SECONDS = 15777000;

    const claimDurationSeconds = options?.expirationDuration || MAX_CLAIM_DURATION_SECONDS;
    if (claimDurationSeconds > MAX_CLAIM_DURATION_SECONDS) {
      throw new Error("Claim duration can\t exceed 6 months");
    }

    const timeNowSeconds = Math.floor(Date.now() / 1000);

    const claims = {
      iss: this.teamId,
      iat: timeNowSeconds,
      exp: timeNowSeconds + claimDurationSeconds,
      aud: "https://appleid.apple.com",
      sub: this.clientId,
    };
    const header = {
      alg: "ES256",
      kid: this.keyIdentifier,
    };
    return jwt.sign(claims, this.privateKey, { algorithm: "ES256", header });
  }

  getAppleSigningKey(kid: string): Promise<SigningKey> {
    return new Promise((resolve, reject) => {
      this.jwksClient.getSigningKey(kid, (err, key) => {
        if (err) {
          reject(err);
        } else {
          resolve(key);
        }
      });
    });
  }

  /**
   * Verify identity of a give JsonWebToken string.
   */
  async verifyIdToken(
    idToken: string,
    options: {
      /**
       * The nonce parameter value needs to include per-session state and be unguessable to attackers.
       */
      nonce?: string;
      /**
       * If you want to handle expiration on your own or decode expired tokens you can set to ignore expiration
       * @default false
       */
      ignoreExpiration?: boolean;
      /**
       * If you want to check subject (sub) a.k.a "user_identifier"
       */
      subject?: string;

      // authorizationCode?: string;
    }
  ): Promise<AppleIdTokenType> {
    if (!idToken) throw new Error("idToken is empty");

    /**
     * Decode the jwt into header and payload so we can find it's appropriate apple public key
     * https://github.com/auth0/node-jsonwebtoken/blob/master/decode.js#L22-L27
     */
    const decodedIdToken = jwt.decode(idToken, { complete: true });

    // We expect that it returns an object, if we get anything else then throw error
    if (!(decodedIdToken !== null && typeof decodedIdToken === "object")) {
      throw new Error("Unexpected results from decoded idToken");
    }

    const kid = decodedIdToken?.header?.kid;
    const alg = decodedIdToken?.header?.alg;

    if (!kid) throw new Error("Missing kid in given idToken");
    if (!alg) throw new Error("Missing alg in given idToken");

    // Will throw if no key found
    const key = await this.getAppleSigningKey(kid);

    // Offload all jwt verification to do the heavy job, we just make sure to pass in needed options
    const jwtClaims = jwt.verify(idToken, key.getPublicKey(), {
      issuer: "https://appleid.apple.com",
      audience: this.clientId,
      algorithms: [alg],
      nonce: options?.nonce,
      ignoreExpiration: options?.ignoreExpiration,
      subject: options?.subject,
    }) as AppleIdTokenType;

    // TODO: possibly implementation of this, as currently the last character is missmatching
    // https://sarunw.com/posts/sign-in-with-apple-4/#authorization-code-(code)-validation
    // if (options?.authorizationCode) {
    //   const hashedCode = crypto.createHash("sha256").update(options.authorizationCode).digest("base64");
    //   const firstHalfOfhashedCode = hashedCode.slice(0, (hashedCode.length - 1) / 2);

    //   if (jwtClaims.c_hash !== firstHalfOfhashedCode) {
    //     throw new Error("Missmatching authorziationCode and c_hash claim");
    //   }
    // }

    return jwtClaims;
  }
}
