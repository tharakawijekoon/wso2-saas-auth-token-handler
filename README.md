# Authentication Handler for Rest API Authentication with Tokens issued by SaaS Service providers

## Background

When using [WSO2 Identity Server](https://wso2.com/identity-and-access-management/) with multi-tenancy, the concept of SaaS service providers comes into play. When a service provider is SaaS enabled, it means that the application is shared among tenants so local users from any tenant will be allowed to log in.

If a SaaS Service Provider is configured with a Self-Contained JWT access token issuer there are some configuration decisions to be made.

1. Should the token be signed with the User's Tenant Key?
2. Should the token be signed with the Service Provider's Tenant Key?

Each option would have its advantages as well disadvantages and would determine on which tenant domain the resulting access token can be used on. 

Note: It is assumed that the following property is added in the deployment.toml.

```
[oauth]
enable_jwt_token_validation_during_introspection = true
```

##  User's Tenant Domain Key
By default in WSO2 Identity Server the tenant's key where the user resides is used to sign the Self-Contained JWT tokens, therefore the resulting access tokens can only be used on the user's tenant domain.

### Benefits
* The user's Tenant APIs(eg consent API) can be called using the access token as the APIs also reside within the user's tenant

### Drawbacks
* Service provider application would need to have all the public certs of the tenants where users reside if the JWT signature is validated on the application end.
* Service provider application should be smart enough to call the user's tenant introspection API instead of calling the SP tenant introspection API.(Generally, self-contained JWT access tokens are not introspected since they are self contained and doing so would defeate their purpose).

##  Service Provider's Tenant Domain Key

The JWT token issuers can be configured to use the service provider's tenant domain key to sign the access tokens. The following configuration should be added in order to achive this.

```
[oauth.access_token]
generate_with_sp_tenant_domain = true
```
### Benefits
* The service provider application would need to deal with only one certificate, that is the certificate of the service provider.
* SP Tenant Domain introspection API can be called to introspect the JWT.

### Drawbacks
* The user's Tenant APIs(eg consent API) cannot be called using the JWT access token.(the signature validations would fail).

# wso2-saas-auth-token-handler

This Authentication Handler makes it possible to combine benefits of the above two options and eliminate the drawbacks. The authentication hanlder is developed using an extension point in Identity Server.

## Logic

When tokens that are signed with the service provider's tenant domain key are used to call user's tenant API, if the token is issued by a SaaS service provider and a cross tenant call is made(the sp tenant and user's tenant is different). This authentication handler would make sure that the Token signature validation is carried out with the service provider's tenant domain key.

## Build

Execute the following command to build the project.

```
mvn clean install
```

## Deploy

Copy and place the built JAR artifact from the <PROJECT_HOME>/target/org.wso2.custom.saas.auth.handler-1.0.0.jar to the <IS_HOME>/repository/components/dropins directory.

Restart/Start the Identity Server.

## Testing

Obtain a Self-Contained JWT access token from a SaaS service provider for a user who is not in the same tenant domain as the service provider. 

```
curl -k --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic ZTVHNlRvRTluME8yQmRXaE42dnpZcUltQUNZYTpqZmJ0N0NydW5xZ0xwQW5LWExxTFFZdzhsMWdh' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=tharaka@tenant1.com' \
--data-urlencode 'password=123abc' \
--data-urlencode 'scope=openid'
```

Call the User's tenant consent receipts API

```
curl --location --request GET 'https://localhost:9443/t/tenant1.com/api/identity/consent-mgt/v1.0/consents/receipts/2024c1c0-d00a-4d57-a17f-fc28fd8953bf' \
--header 'Authorization: Bearer eyJ4NXQiOiJaVFZpWWpKaU1EQTFOVGxpTXpZME5HWmhaakpoWVdZd1pESXhaV1JoWXpZeFlUVmxOekpqWWpNNU5qVXhPVEZpTldSaU1HUTVPRGszT1RJMFpqRTRPUSIsImtpZCI6IlpUVmlZakppTURBMU5UbGlNelkwTkdaaFpqSmhZV1l3WkRJeFpXUmhZell4WVRWbE56SmpZak01TmpVeE9URmlOV1JpTUdRNU9EazNPVEkwWmpFNE9RX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ0aGFyYWthIiwiYXV0IjoiQVBQTElDQVRJT05fVVNFUiIsImF1ZCI6ImU1RzZUb0U5bjBPMkJkV2hONnZ6WXFJbUFDWWEiLCJjb3VudHJ5IjoiU3JpIExhbmthIiwibmJmIjoxNjExNTEzNTM3LCJhenAiOiJlNUc2VG9FOW4wTzJCZFdoTjZ2ellxSW1BQ1lhIiwic2NvcGUiOiJvcGVuaWQiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE2MTE1MTcxMzcsImlhdCI6MTYxMTUxMzUzNywianRpIjoiNTQxNGY2MGUtZWRkOS00MTVmLTgxNDAtOGRlOGRmNmY1NGEyIn0.JEP1juSwxaV1dWPUyJj4SKbnAR5yGvm924iVRClm7FOnzKTzP8wwEo9SPcHg9uU_P1elzxcJKyEGwe87eKlOnWoDSXjxZ2d5W5RpXMuGXOAPPuT_EFIDZgf3bt7BwZ1q4DQWIXlO2y5O_AbViosTJEtPzJNaM-vVD66ky1VOcY3wUPXkrW53VSSVzq2RnAAWwkJpNiyhNJftChD7_Wb3W01zs_Hidl9u4rQPdzNqzKyLTEChBuICDiQo3LTDp6rXCIQcFROETbd7zF9-42mHmcDCpkUHnfl03NRaWuxajD_JhmNgxJCDcvW_tfjuoX5Xz714cGPaO-_IDaJYe79oJQ' \
--header 'accept: application/json'
```

