Identity provider authentication
--------------------------------

## Overview

   Identity provider authentication will take care of authenticating the user/account in  third party server, based on the response it will authorize user/account in Gooru system.

**Supported identity provider methods**

   - Google
   - WSFED
   - SAML
   - OAuth2

**Configuration**

   ```config.json``` file has  all the configuration details like callback urls, client ID or Key etc.

## How to setup ?

   - Install  nodejs
   - Clone the project
   - In home path of the project install all packages, using below command,
   - ```npm install && npm install -g forever```

## How to setup Shibboleth IdP ?

   - Generate the metadata using ```/api/nucleus-auth-idp/v1/shibboleth/generateMetadata``` from the environment
     where this service is running e.g.```http://www.gooru.org/api/nucleus-auth-idp/v1/shibboleth/generateMetadata```
   - Share the metadata with partners to upload on Shibboleth IdP
   - There is no need to creating a new route for a new partner. Partners are required to pass the shibboleth IdP
     entryPoint in the request and that will redirect user to their IdP for authentication
     e.g. ```http://www.gooru.org/api/nucleus-auth-idp/v1/shibboleth?entryPoint=https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO```

## How to setup OAuth2 ?

  - Oauth2 sample configuration settings for github, Note: Settings will change based  on third party Oauth application setup.

```
   {
      "scope":"user",
      "profile":{
      "api_url":"https://api.github.com/user",
      "response_mapper":{
         "email":"email",
         "username":"login",
         "first_name":"name",
         "reference_id":"id"
      },
      "auth_header_placeholder":"token [tokenValue]"
      },
      "client_id":"cf9cf76570586ee33050",
      "token_url":"https://github.com/login/oauth/access_token",
      "callback_url":"http://localhost:3000/api/nucleus-auth-idp/v1/oauth2/adl/callback",
      "client_secret":"0ba11d47df6f7c2047b9fe0d71cefa2cbb9c51e0",
      "home_page_url":"https://staging.gooru.org/teacher-home",
      "response_type":"code",
      "authorization_url":"https://github.com/login/oauth/authorize"
   }
```
   - Setup Oauth application configuration in github.

       1) Navigate to github  [developer settings](https://github.com/settings/developers).
       2) Create new OAuth application, update the necessary values and save, See the sample value of updates below, Once you save you will get client id and secret.
       
       ![alt text](https://github.com/Gooru/nucleus-auth-identity-provider/blob/develop/Oauth-github-sample-setup.png)
       
