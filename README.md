# quave:apple-oauth

## Ready for Meteor 3.0 at 4.0.0

Sign in with Apple handler with native cordova plugin handler. forked from jramer/apple-oauth

# Quick Start

Add all required packages: quave:apple-oauth quave:accounts-apple service-configuration accounts-oauth

Follow the next section fully.


## Config

Look here for a good example how to get these:
[https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple](https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple)

The `secret` private key needs to have \n instead of newlines in the correct places.
The `redirectUri` needs to be https. [ngrok](https://ngrok.com)/[serveo](https://serveo.net) works for development but you need to have the uri added in you apple dev account in the return urls.

Place the following in your settings.json:


```
"apple": {
  "nativeClientId": "< your app id (mobile) >",
  "clientId": "< your service id (for web) >",
  "teamId": "",
  "keyId": "",
  "secret": "-----BEGIN PRIVATE KEY-----\nABC\nABC\nABC\nABC\n-----END PRIVATE KEY-----",
  "redirectUri": "https://abc.def/_oauth/apple"
},
```

Set in the database on Meteor.startup:

```
Meteor.startup(async () => {
    await Accounts.loginServiceConfiguration.upsertAsync(
      {
        service: 'apple',
      },
      {
        $set: Meteor.settings.apple,
      }
    );
})
```


And log in calling:
```
  Meteor.loginWithApple({
    requestPermissions: ['name', 'email'],
  });
```

### Login without Cordova

If you are using `react-native` or any other tool besides Cordova, you can also use this library.
You just need to fetch the credentials from Apple, and then send it to the Meteor server:
```
Meteor.call(
          "login",
          {
            ...credentials,
            code: credentials[supportsIos ? 'authorizationCode' : 'code'],
            methodName: `${supportsIos ? 'native' : 'web'}-apple`,
          }, (err) => {...})
```

## React-native
In react native you could log in using `invertase/react-native-apple-authentication` and `meteorrn/core`:
```
Meteor.loginWithApple = async () => {
    const credentials = await appleAuth.performRequest({
    requestedOperation: appleAuth.Operation.LOGIN,
    requestedScopes: [appleAuth.Scope.FULL_NAME, appleAuth.Scope.EMAIL],
  });
  
  return new Promise((resolve, reject) => {
      Meteor._startLoggingIn();
      Meteor.call(
          "login",
          {
            ...credentials,
            code: credentials.authorizationCode,
            // For android you need to use 'web-apple' as the method name.
            methodName: 'native-apple',
          },
          (error: any, response: unknown) => {
            Meteor._endLoggingIn();
            Meteor._handleLoginCallback(error, response);

            if (error) {
              return reject(error);
            }

            resolve(response);
          }
      );
    });
}
```

## Use multiple services ids

Because of a limitation imposed by apple, organization accounts can set up to 100 domains+redirect urls, and individuals only 10.

This is a bummer if you have a whitelabel app. With this lib you can use multiple services ids, like the following:

- Create a new service id on apple developers and set it on your settings.json file:

```
"apple": {
  "nativeClientId": "< your app id (mobile) >",
  "clientId": "< your service id (for web) >",
  "clientId-2": "< your service id (for web) >",
  "clientId-3": "< your service id (for web) >",
  "clientId-4": "< your service id (for web) >",
  "clientId-5": "< your service id (for web) >",
  "teamId": "",
  "keyId": "",
  "secret": "-----BEGIN PRIVATE KEY-----\nABC\nABC\nABC\nABC\n-----END PRIVATE KEY-----",
  "redirectUri": "https://abc.def/_oauth/apple"
},
```
They need to be set at the same nativeClientId, otherwise the secret and keyIds would be different. We don't support multiple native ids yet.

- Login with:
```
  Meteor.loginWithApple({
    requestPermissions: ['name', 'email'],
    shard: "2"
  });
```
This will use the clientId-2 id, and so on.

## Use multiple native client ids

The use case for this feature is a whitelabel server, serving oauth credentials for multiple native apps. In this case, we need to have one service configuration per native app id.

```json
"apple": {
    "secret": : [ 
        {"appId": "br.com.anotherAppId2", "secret" : "-----BEGIN PRIVATE KEY-----\nABC\nABC\nABC\nABC\n-----END PRIVATE KEY-----"}
        {"appId": "br.com.anotherAppId", "secret": "-----BEGIN PRIVATE KEY-----\nABC\nABC\nABC\nABC\n-----END PRIVATE KEY-----"}
    ],
    "apps": [
        {
            "appId": "br.com.anotherAppId",
            "nativeClientId": "< your app id (mobile) >",
            "clientId": "< your service id (for web) >",
            "clientId-2": "< your service id (for web) >",
            "teamId": "",
            "keyId": "",
            "redirectUri": "https://abc.def/_oauth/apple"
        },
        {
            "appId": "br.com.anotherAppId2",
            "nativeClientId": "< your app id (mobile) >",
            "clientId": "< your service id (for web) >",
            "clientId-2": "< your service id (for web) >",
            "teamId": "",
            "keyId": "",
            "redirectUri": "https://abc.def/_oauth/apple"
        }
    ]
}
```




## FAQ

1. My native app doesn't log in: Check if you built your app with the "Sign in with Apple" capability enabled, and if the provisioning profile also supports it.
2. My web app doesn't log in: Check if the keyId/secret/clientId is correct, also check if you have added the redirectUri to the list of authorized redirects, and that it ends with _oauth/apple
3. I'm receiving an " " string (note the space) as the name: The user didn't give your app the permission to see the name. Please note that this can happen, and you should handle this case in your app.
