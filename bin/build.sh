#! /bin/bash
# Build a docker image
cd ..
docker build -t pyengine/keycloak-oidc .
docker tag pyengine/keycloak pyengine/keycloak-oidc:1.1
docker tag pyengine/keycloak spaceone/keycloak-oidc:1.1
