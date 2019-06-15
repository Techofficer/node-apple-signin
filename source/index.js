const { URL } = require('url');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const NodeRSA = require('node-rsa');
const request = require('request-promise-native');

const ENDPOINT_URL = 'https://appleid.apple.com';
const DEFAULT_SCOPE = 'email';
const TOKEN_ISSUER = 'https://appleid.apple.com';

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

const getApplePublicKey = async () => {
  const url = new URL(ENDPOINT_URL);
  url.pathname = '/auth/keys';

  const data = await request({ url: url.toString(), method: 'GET' });
  const key = JSON.parse(data).keys[0];

  const pubKey = new NodeRSA();
  pubKey.importKey({ n: Buffer.from(key.n, 'base64'), e: Buffer.from(key.e, 'base64') }, 'components-public');
  return pubKey.exportKey(['public']);
};

const verifyIdToken = async (idToken, clientID) => {
  const applePublicKey = await getApplePublicKey();
  const jwtClaims = jwt.verify(idToken, applePublicKey, { algorithms: 'RS256' });

  if (jwtClaims.iss !== TOKEN_ISSUER) throw new Error('id token not issued by correct OpenID provider - expected: ' + TOKEN_ISSUER + ' | from: ' + jwtClaims.iss);
  if (clientID !== undefined && jwtClaims.aud !== clientID) throw new Error('aud parameter does not include this client - is: ' + jwtClaims.aud + '| expected: ' + clientID);
  if (jwtClaims.exp < (Date.now() / 1000)) throw new Error('id token has expired');

  return jwtClaims;
};


module.exports = {
  getAuthorizationUrl,
  getAuthorizationToken,
  refreshAuthorizationToken,
  verifyIdToken,
  getClientSecret
};
