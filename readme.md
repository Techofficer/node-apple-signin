# Sign in with Apple

Hopefully your go-to library for implementing [*Sign In With Apple Rest API*](https://developer.apple.com/documentation/sign_in_with_apple) in Node.js

> See comparison table(<todo-link>) why  you should choose <this-package>  over other `apple-xxx` package.

## Installation

Install the module using [npm](http://npmjs.com):

```bash
npm install --save apple-signin
```



## Documentation

>  Library is built on typescript and has well documented source code. This will provide a zero-effort developer expierence within your existing code editors. But the library also provides autogenered documentation using [typedoc](https://typedoc.org/).

- [Full Documentation](https://renarsvilnis.github.io/node-apple-signin/modules/_applesignin_.html) 

## Usage


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
http://localhost:3000/auth/apple/callback?code=somecode&state=123.

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
// TODO: add documentation to compare state

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

## Examples

Developers using the popular [Express](http://expressjs.com) web framework can refer to an [example](https://github.com/Techofficer/express-apple-signin) as a starting point for their own web applications.



## Reason to choose <this-packege> over others

> There are many libraries out now most of them aren't feature full and/or abandoned. <this-package> built from `apple-signin` but from the ground up.

The only other library I'd consider feature-full and ready to use is [apple-signin-auth](https://github.com/A-Tokyo/apple-signin-auth) by [A-Tokyo](https://github.com/A-Tokyo). Others seem to have missing key feature.



|                               | <this-package>                                               | [apple-signin-auth](https://github.com/A-Tokyo/apple-signin-auth) | [apple-auth](https://github.com/ananay/apple-auth)           | [apple-signin](https://github.com/Techofficer/node-apple-signin) |
| ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Feature Full                  | ✅                                                            | ✅ (missing some function options)                            | ❌                                                            | ❌                                                            |
| Apple Public Key Caching      | ✅ (cache per class instance)                                 | ✅ (global cache)                                             | ❌                                                            | ❌                                                            |
| Passport.js library           | ❌                                                            | ❌                                                            | ✅                                                            | ✅                                                            |
| Typed Support                 | ✅ (typescript based)                                         | ✅ (flow based)                                               | ❌                                                            | ❌                                                            |
| API Documentation             | ✅ (auto generated docs using [typedoc](https://typedoc.org/)) | ❌                                                            | ❌                                                            | ❌                                                            |
| Usage Examples                | ✅                                                            | ✅                                                            | ✅                                                            | ✅                                                            |
| Tools for easier contributors | ✅ (typescript, eslint, prettier, jest)                       | ✅ (flow, eslint, prettier, jest)                             | ❌                                                            | ❌                                                            |
| Stats                         | <TODO-ADD-ONCE-PUBLICHED>                                    | [![NPM](https://nodei.co/npm/apple-signin-auth.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/apple-signin-auth/) | [![NPM](https://nodei.co/npm/apple-auth.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/apple-auth/) | [![NPM](https://nodei.co/npm/apple-signin.png)](https://nodei.co/npm/apple-signin/) |



## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

<TODO-add-guide>

## License

[The MIT License](https://choosealicense.com/licenses/mit/)

Copyright (c) 2020 Renārs Vilnis

## Support

If you have any questions or need help with integration, then you can contact me by email
[renars.vilnis@gmail.com](renars.vilnis@gmail.com).