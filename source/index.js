const { URL } = require('url');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const jwksRsa = require('jwks-rsa');
const request = require('request-promise-native');

const ENDPOINT_URL = 'https://appleid.apple.com';
const DEFAULT_SCOPE = 'email';
const TOKEN_ISSUER = 'https://appleid.apple.com';

const jwksClient = jwksRsa({
  jwksUri: ENDPOINT_URL + '/auth/keys',
  cache: true
});

const getAuthorizationUrl = (options = {}) => {
  if (!options.clientID) throw Error('clientID is empty');
  if (!options.redirectUri) throw Error('redirectUri is empty');

  const url = new URL(ENDPOINT_URL);
  url.pathname = '/auth/authorize';

  url.searchParams.append('response_type', 'code');
  url.searchParams.append('state', options.state || 'state');
  url.searchParams.append('client_id', options.clientID);
  url.searchParams.append('redirect_uri', options.redirectUri);

  if (options.scope){
    url.searchParams.append('scope', 'openid ' + options.scope);
  } else {
    url.searchParams.append('scope', 'openid');
  }

  return url.toString();
};

const getClientSecret = options => {
  if (!options.clientID) throw new Error('clientID is empty');
  if (!options.teamId) throw new Error('teamId is empty');
  if (!options.keyIdentifier) throw new Error('keyIdentifier is empty');
  if (!options.privateKeyPath) throw new Error('privateKeyPath is empty');
  if (!fs.existsSync(options.privateKeyPath)) throw new Error("Can't find private key");

  const timeNow = Math.floor(Date.now() / 1000);

  const claims = {
    iss: options.teamId,
    iat: timeNow,
    exp: timeNow + 15777000,
    aud: ENDPOINT_URL,
    sub: options.clientID,
  };

  const header = { alg: 'ES256', kid: options.keyIdentifier };
  const key = fs.readFileSync(options.privateKeyPath);

  return jwt.sign(claims, key, { algorithm: 'ES256', header });
};

const getAuthorizationToken = async (code, options) => {
  if (!options.clientID) throw new Error('clientID is empty');
  if (!options.redirectUri) throw new Error('redirectUri is empty');
  if (!options.clientSecret) throw new Error('clientSecret is empty');

  const url = new URL(ENDPOINT_URL);
  url.pathname = '/auth/token';

  const form = {
    client_id: options.clientID,
    client_secret: options.clientSecret,
    code,
    grant_type: 'authorization_code',
    redirect_uri: options.redirectUri,
  };

  const body = await request({ url: url.toString(), method: 'POST', form });
  return JSON.parse(body);
};

const refreshAuthorizationToken = async (refreshToken, options) => {
  if (!options.clientID) throw new Error('clientID is empty');
  if (!options.clientSecret) throw new Error('clientSecret is empty');

  const url = new URL(ENDPOINT_URL);
  url.pathname = '/auth/token';

  const form = {
    client_id: options.clientID,
    client_secret: options.clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  };

  const body = await request({ url: url.toString(), method: 'POST', form });
  return JSON.parse(body);
};

const getAppleSigningKey = (kid) => {
  return new Promise((resolve, reject) => {
    jwksClient.getSigningKey(kid, (err, key) => {
      if (err) {
        reject(err);        
      } else {
        resolve(key);
      }
    });
  });
}

const verifyIdToken = async (idToken, clientID) => {
  const decodedIdToken = jwt.decode(idToken, { complete: true });
  const { kid, alg } = decodedIdToken.header;
  const key = await getAppleSigningKey(kid);
  const publicKey = key.getPublicKey();
  const jwtClaims = jwt.verify(idToken, publicKey, {
    issuer: TOKEN_ISSUER,
    audience: clientID,
    algorithms: [alg]
  });  

  return jwtClaims;
};

module.exports = {
  getAuthorizationUrl,
  getAuthorizationToken,
  refreshAuthorizationToken,
  verifyIdToken,
  getClientSecret
};
