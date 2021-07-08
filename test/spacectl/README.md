# Configuration

## Register Plugin

This is for registering plugin in local repository or portal.

Run as root domain

~~~
spacectl exec register repository.Plugin -c register_plugin.yaml
~~~

## Create Keycloak Domain

Create  Local Domain

~~~
spacectl exec create identity.Domain -f create_domain.yaml
~~~

## Change Auth Plugin

* Update openid-configuration
* Update client_id
* Update client_secret

~~~
spacectl exec change_auth_plugin identity.Domain -c change_auth_plugin.yaml
~~~
