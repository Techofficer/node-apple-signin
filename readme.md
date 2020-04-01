# Sign in with Apple

Hopefully your go-to library for implementing [_Sign In With Apple Rest API_](https://developer.apple.com/documentation/sign_in_with_apple) in Node.js.

> See [comparison table](https://github.com/renarsvilnis/apple-sign-in#comparison-to-other-apple-sign-in-libraries) why you should choose `apple-sign-in` over other `apple-xxx` package.

Supports Node.js `>= 10.x.x`

## Installation

Install the module using [npm](http://npmjs.com):

```bash
npm install --save apple-sign-in
yarn add apple-sign-in
```

## Documentation

Library is built on typescript and has well documented source code. This will provide a zero-effort developer expierence within your existing code editors. But the library also provides autogenered documentation using [typedoc](https://typedoc.org/).

- [Full Documentation](https://renarsvilnis.github.io/apple-sign-in/modules/_applesignin_.html)

## Usage

<TODO-update-usage-docs>

### 0. Prerequisites

1. You should be enrolled in [Apple Developer Program](https://developer.apple.com/programs/).
2. Please have a look at [Apple documentation](https://developer.apple.com/sign-in-with-apple/get-started/) related to "Sign in with Apple" feature.
3. You should create App ID and Service ID in your Apple Developer Account.
4. You should generate private key for your Service ID in your Apple Developer Account.

More detail about configuration can be found in [blog post](https://medium.com/@artyomefremov/add-sign-in-with-apple-button-to-your-website-today-part-1-12ed1444623a?postPublishedType=initial) and [Apple docs](https://help.apple.com/developer-account/#/dev1c0e25352).

### 1. Get authorization URL

Start "Sign in with Apple" flow by redirecting user to the authorization URL.

```javascript
const appleSignin = require("apple-signin");

const options = {
  clientID: "com.gotechmakers.auth.client", // identifier of Apple Service ID.
  redirectUri: "http://localhost:3000/auth/apple/callback",
  state: "123", // optional, An unguessable random string. It is primarily used to protect against CSRF attacks.
  scope: "email", // optional, default value is "email".
};

const authorizationUrl = appleSignin.getAuthorizationUrl(options);
```

Alternatively, you can use [Sign In with Apple](https://developer.apple.com/documentation/signinwithapplejs) browser javascript library.

### 2. Get access token

2.1. Retrieve "code" query param from URL string when user is redirected to your site after successful sign in with Apple. Example:
[http://localhost:3000/auth/apple/callback?code=somecode&state=123](http://localhost:3000/auth/apple/callback?code=somecode&state=123).

2.2. Exchange retrieved "code" to user's access token.

More detail can be found in [Apple docs](https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens).

```javascript
const clientSecret = appleSignin.getClientSecret({
  clientID: "com.gotechmakers.auth.client", // identifier of Apple Service ID.
  teamId: "teamId", // Apple Developer Team ID.
  privateKeyPath: "/var/www/app/AuthKey_XXX.p8", // path to private key associated with your client ID.
  keyIdentifier: "XXX", // identifier of the private key.
});

const options = {
  clientID: "com.gotechmakers.auth.client", // identifier of Apple Service ID.
  redirectUri: "http://localhost:3000/auth/apple/callback", // use the same value which you passed to authorisation URL.
  clientSecret: clientSecret,
};

appleSignin
  .getAuthorizationToken(code, options)
  .then((tokenResponse) => {
    console.log(tokenResponse);
  })
  .catch((error) => {
    console.log(error);
  });
```

Result of `getAuthorizationToken` command is a JSON object representing Apple's [TokenResponse](https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse):

```javascript
{
    access_token: "ACCESS_TOKEN", // A token used to access allowed data.
    token_type: 'Bearer', // It will always be Bearer.
    expires_in: 3600, // The amount of time, in seconds, before the access token expires.
    refresh_token: "REFRESH_TOKEN", // used to regenerate new access tokens. Store this token securely on your server.
    id_token: "ID_TOKEN" // A JSON Web Token that contains the user’s identity information.
}
```

### 3. Verify token signature and get unique user's identifier

```javascript
appleSignin
  .verifyIdToken(tokenResponse.id_token, clientID)
  .then((result) => {
    const userAppleId = result.sub;
  })
  .catch((error) => {
    // Token is not verified
    console.log(error);
  });
```

### 4. Refresh access token after expiration

```javascript
const clientSecret = appleSignin.getClientSecret({
  clientID: "com.gotechmakers.auth.client", // identifier of Apple Service ID.
  teamId: "teamId", // Apple Developer Team ID.
  privateKeyPath: "/var/www/app/AuthKey_XXX.p8", // path to private key associated with your client ID.
  keyIdentifier: "XXX", // identifier of the private key.
});

const options = {
  clientID: "com.gotechmakers.auth.client", // identifier of Apple Service ID.
  clientSecret: clientSecret,
};

appleSignin
  .refreshAuthorizationToken(refreshToken, options)
  .then((result) => {
    const newAccessToken = result.access_token;
  })
  .catch((error) => {
    console.log(error);
  });
```

<!-- ## Examples

Developers using the popular [Express](http://expressjs.com) web framework can refer to an [example](https://github.com/Techofficer/express-apple-signin) as a starting point for their own web applications. -->

## Comparison to other "apple sign in" libraries

There are many already packages on npm with very similar names. Most of them are missing featuers and/or abandoned. This package takes inspiration from `apple-signin` and implements features/fixes while comparing to other libraries.

The only other library I'd consider feature-full and ready to use besides this one is [apple-signin-auth](https://github.com/A-Tokyo/apple-signin-auth) by [A-Tokyo](https://github.com/A-Tokyo), seem to have missing key features.

|                               | apple-sign-in                                                  | [apple-signin-auth](https://github.com/A-Tokyo/apple-signin-auth)                                                                         | [apple-auth](https://github.com/ananay/apple-auth)                                                                          | [apple-signin](https://github.com/Techofficer/node-apple-signin)                    |
| ----------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Feature Full                  | ✅                                                             | ✅ (missing some minor options)                                                                                                           | ❌                                                                                                                          | ❌                                                                                  |
| Apple Public Key Caching      | ✅ (cache per class instance)                                  | ✅ (global cache)                                                                                                                         | ❌                                                                                                                          | ❌                                                                                  |
| Passport.js library           | ❌ (comming-soon)                                              | ❌                                                                                                                                        | ✅                                                                                                                          | ✅                                                                                  |
| Typed Support                 | ✅ (typescript based)                                          | ✅ (flow based)                                                                                                                           | ❌                                                                                                                          | ❌                                                                                  |
| API Documentation             | ✅ (auto generated docs using [typedoc](https://typedoc.org/)) | ❌                                                                                                                                        | ❌                                                                                                                          | ❌                                                                                  |
| Usage Examples                | ✅                                                             | ✅                                                                                                                                        | ✅                                                                                                                          | ✅                                                                                  |
| Tools for easier contributors | ✅ (typescript, eslint, prettier, jest)                        | ✅ (flow, eslint, prettier, jest)                                                                                                         | ❌                                                                                                                          | ❌                                                                                  |
| Stats                         | [![NPM](https://nodei.co/npm/apple-sign-in.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/apple-sign-in/)                                    | [![NPM](https://nodei.co/npm/apple-signin-auth.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/apple-signin-auth/) | [![NPM](https://nodei.co/npm/apple-auth.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/apple-auth/) | [![NPM](https://nodei.co/npm/apple-signin.png)](https://nodei.co/npm/apple-signin/) |

## Contributing

Pull requests are always welcomed. 🙇🏻‍♂️ Please open an issue first to discuss what you would like to change.

Package has a pre-commit git hook that does typechecking, linting, unit testing and doc building (if see source code changes).

### Helper scripts

```bash
# Build library, will create a library in /lib folder
npm run build

# Run unit tests
npm run test
npm run test:watch # watch mode

# Run typecheck and linter
npm run lint

# Attempts to fix all formatting and linting issues
npm run format

# Build docs
npm run docs

# Inspect documentation localy visit http://127.0.0.1:8080
npm run docs:serve

# By default docs are automatically built and added on pre-commit hook,
# if it sees staged changes to any /src files,
# you can override the logic by forcing to build docs by passing environmental
FORCE_DOCS=true git commit -m 'My awesome change'

# Commit but ignore ship the git hooks
git commit -m 'My awesome change' --no-verify
```

## License

[The MIT License](https://choosealicense.com/licenses/mit/)

Copyright (c) 2020 Renārs Vilnis

## Support

If you have any questions or need help with integration, then you can contact me by email
[renars.vilnis@gmail.com](renars.vilnis@gmail.com).
