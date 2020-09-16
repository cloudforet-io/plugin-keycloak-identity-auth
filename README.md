# plugin-keycloak-oidc

Plugin for Keycloak OpenID Connector


# Configuration

~~~python
options(dict) = {
	'client_id': 'client_id text',
	'openid-configuration': 'https://<SSO domain>/auth/realms/<Your Realm>/.well-known/openid-configuration',
	'domain': 'domain name'
	}
~~~


## Example

~~~python
options = {
	'client_id': '<sso_client_id_text>',
	'openid-configuration': 'https://sso.example.com/auth/realms/spaceone/.well-known/openid-configuration',
	'domain': 'megazone.com'
	}
~~~

# Release Note

## Version 1.1

Support New Auth API
* Auth.init
* Auth.verify
