# plugin-keycloak-oidc

Plugin for Keycloak OpenID Connector


# Configuration

~~~python
options(dict) = {
	'openid-configuration': 'https://<SSO domain>/auth/realms/<Your Realm>/.well-known/openid-configuration',
	'auth_type': 'keycloak_oidc'
	}

secret_data = {
	'client_id': 'client_id text',
	'client_secret': 'client secret text'
}

schema = 'oauth2_client_credentials'
~~~


## Example

How to create client_id, client_secret.

See https://github.com/spaceone-dev/plugin-keycloak-oidc/wiki/Keycloak-configuration-example


~~~python
options = {
	'openid-configuration': 'https://sso.example.com/auth/realms/MY_DOMAIN/.well-known/openid-configuration',
	'auth_type': 'keycloak_oidc'
	}
secret_id='secret-11111111'
schema='oauth2_client_credentials'
~~~

# Auth.init

If you init plugin, the response looks like

~~~
{'metadata': {
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

## Version 1.0

Support New Auth API
* Auth.init
* Auth.verify
* Auth.find
* Auth.login
