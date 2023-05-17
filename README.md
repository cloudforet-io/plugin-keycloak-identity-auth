# plugin-keycloak-identity-auth

Plugin for Keycloak OpenID Connector


# Configuration

~~~python
options = {
    'openid-configuration': 'https://<SSO domain>/auth/realms/<Your Realm>/.well-known/openid-configuration',
    'auth_type': 'keycloak_oidc',
    'client_id': 'CLIENT ID for login',
    'field_mapper': {...},
    'verify': True
}

secret_data = {
    'client_id': 'CLIENT ID for find users',
    'client_secret': 'client secret text'
}
~~~

## Field Mapper
`field_mapper` setting allows you to change user field information.

## Verify
If you set `verify` to `False`, the keycloak server's certificate will not be verified. 
  
### Default Settings
~~~python
{
    'field_mapper (optional)': {
        'user_id': 'username',
        'name': 'name',
        'email': 'email'
    }
}
~~~
### Available Keycloak Fields
  * username
  * email
  * firstName
  * lastName
  * name: `{firstName} {lastName}`

## Example

To enable keycloak-oidc plugin,
use identity.Domain.change_auth_plugin API.


~~~bash
spacectl exec change_auth_plugin identity.Domain -f keycloak.yaml
~~~

Example YAML file

See https://github.com/spaceone-dev/plugin-keycloak-oidc/wiki/Keycloak-configuration-example

~~~yaml
plugin_info:
  options:
    auth_type: keycloak_oidc
    openid-configuration: https://sso.example.com/auth/realms/test-domain/.well-known/openid-configuration
    client_id: test_client_id
  plugin_id: plugin-keycloak-identity-auth
  secret_data:
    client_id: test_client_id2
    client_secret: 11111111-1111-1111-1111-111111111111
  version: '1.0'
~~~

# Auth.init

If you init plugin, the response looks like

~~~
{
    'metadata': {
        'authorization_endpoint': 'https://sso.example.com/auth/realms/MY_DOMAIN/protocol/openid-connect/auth',
        'end_session_endpoint': 'https://sso.example.com/auth/realms/MY_DOMAIN/protocol/openid-connect/logout',
        'issuer': 'https://sso.example.com/auth/realms/MY_DOMAIN',
        'token_endpoint': 'https://sso.example.com/auth/realms/MY_DOMAIN/protocol/openid-connect/token',
        'userinfo_endpoint': 'https://sso.example.com/auth/realms/MY_DOMAIN/protocol/openid-connect/userinfo',
        'realm': 'MY_DOMAIN',
        'user_find_url': 'https://sso.example.com/auth/admin/realms/MY_DOMAIN/user'
    }
}
~~~

# Release Note

## Version 1.3
- Add 'field_mapper' option to change fields for authenticated users.

## Version 1.0

Support New Auth API
* Auth.init
* Auth.verify
* Auth.find
* Auth.login
